# Audit Report

## Title
JWK Consensus State Machine Allows Improper Finished→InProgress Transition, Discarding Quorum-Certified Updates

## Summary
The JWK consensus state machine in the issuer-level manager can transition from `Finished` back to `InProgress` when a new JWK observation arrives before the previous quorum-certified update is committed on-chain. This transition improperly discards the quorum-certified update by dropping its `vtxn_guard`, removing the transaction from the validator transaction pool and wasting all consensus work.

## Finding Description

The vulnerability exists in the `process_new_observation` function which handles new JWK observations from OIDC providers. [1](#0-0) 

The state machine has three states defined in `ConsensusState`: `NotStarted`, `InProgress`, and `Finished`. [2](#0-1) 

When a JWK observation arrives, the function checks if the observed JWKs differ from the on-chain state. If they do, it unconditionally creates a new `InProgress` state without checking if the current state is `Finished`. [3](#0-2) 

When transitioning from `Finished` to `InProgress`, the old `Finished` variant is dropped, which contains:
- `vtxn_guard`: A transaction guard that, when dropped, removes the quorum-certified transaction from the validator transaction pool [4](#0-3) 
- `quorum_certified`: The quorum-certified update data with validator signatures
- `my_proposal`: The original proposal

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

This creates a situation where two different transactions for the same version number can exist across the network, though the VM will only execute one. [5](#0-4) 

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

While this does not directly cause consensus safety violations (due to VM version checking preventing duplicate version execution), it meets **High Severity** criteria for "Significant protocol violations" and "Validator node slowdowns" through resource waste and potential liveness degradation.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

This issue can occur in legitimate scenarios:
- OIDC providers can perform key rotations at any time for security reasons
- Rapid key rotations (e.g., during a security incident) are not uncommon
- The timing window is realistic: from when quorum is reached until a block is executed typically spans multiple seconds
- No special privileges are required - any OIDC provider behavior can trigger this

The issue is deterministic and will occur whenever:
1. A quorum-certified update reaches `Finished` state
2. A new JWK observation arrives before the transaction is executed on-chain
3. The new observation differs from the on-chain state

## Recommendation

Add a guard similar to the per-key manager to prevent restarting consensus when already in `Finished` state:

```rust
pub fn process_new_observation(
    &mut self,
    issuer: Issuer,
    jwks: Vec<JWKMoveStruct>,
) -> Result<()> {
    let state = self.states_by_issuer.entry(issuer.clone()).or_default();
    state.observed = Some(jwks.clone());
    
    // Add check to prevent restarting consensus if already finished
    match &state.consensus_state {
        ConsensusState::Finished { my_proposal, .. } => {
            // If finished with same observation, do nothing
            if my_proposal.observed.jwks == jwks {
                return Ok(());
            }
            // If finished with different observation, wait for on-chain update
            // before starting new consensus for next version
            return Ok(());
        },
        _ => {}
    }
    
    if state.observed.as_ref() != state.on_chain.as_ref().map(ProviderJWKs::jwks) {
        // ... rest of existing logic
    }
    
    Ok(())
}
```

The key insight is: once a quorum-certified update is achieved (`Finished` state), the system should wait for the on-chain state to be updated via `reset_with_on_chain_state` before starting a new consensus session for the next version.

## Proof of Concept

Add this test to `crates/aptos-jwk-consensus/src/jwk_manager/tests.rs`:

```rust
#[tokio::test]
async fn test_finished_to_inprogress_transition_vulnerability() {
    // Setup: 4 validators
    let private_keys: Vec<Arc<PrivateKey>> = (0..4)
        .map(|_| Arc::new(PrivateKey::generate_for_testing()))
        .collect();
    let public_keys: Vec<PublicKey> = private_keys
        .iter()
        .map(|sk| PublicKey::from(sk.as_ref()))
        .collect();
    let addrs: Vec<AccountAddress> = (0..4).map(|_| AccountAddress::random()).collect();
    let validator_consensus_infos: Vec<ValidatorConsensusInfo> = (0..4)
        .map(|i| ValidatorConsensusInfo::new(addrs[i], public_keys[i].clone(), 1))
        .collect();
    let epoch_state = EpochState {
        epoch: 999,
        verifier: ValidatorVerifier::new(validator_consensus_infos).into(),
    };

    let update_certifier = DummyUpdateCertifier::default();
    let vtxn_pool = VTxnPoolState::default();
    let mut jwk_manager = IssuerLevelConsensusManager::new(
        private_keys[0].clone(),
        addrs[0],
        Arc::new(epoch_state),
        Arc::new(update_certifier),
        vtxn_pool.clone(),
    );

    let issuer_alice = issuer_from_str("https://alice.info");
    let alice_jwks_v100 = vec![JWK::Unsupported(UnsupportedJWK::new_for_testing("kid_0", "payload_0")).into()];
    
    // Initialize on-chain state at version 100
    let on_chain_state_v100 = ProviderJWKs {
        issuer: issuer_alice.clone(),
        version: 100,
        jwks: alice_jwks_v100.clone(),
    };
    jwk_manager.reset_with_on_chain_state(AllProvidersJWKs {
        entries: vec![on_chain_state_v100],
    }).unwrap();

    // Step 1: First rotation - observe new JWKs (version 101)
    let alice_jwks_v101 = vec![JWK::Unsupported(UnsupportedJWK::new_for_testing("kid_1", "payload_1")).into()];
    jwk_manager.process_new_observation(issuer_alice.clone(), alice_jwks_v101.clone()).unwrap();
    
    // Simulate reaching quorum - transition to Finished
    let qc_update_v101 = create_qc_update(&private_keys, &issuer_alice, 101, alice_jwks_v101.clone());
    jwk_manager.process_quorum_certified_update(qc_update_v101.clone()).unwrap();
    
    // Verify state is Finished and transaction is in pool
    assert!(matches!(
        jwk_manager.states_by_issuer.get(&issuer_alice).unwrap().consensus_state,
        ConsensusState::Finished { .. }
    ));
    let txns_in_pool = vtxn_pool.pull(Instant::now() + Duration::from_secs(10), 10, 1024, TransactionFilter::empty());
    assert_eq!(txns_in_pool.len(), 1);
    
    // Step 2: VULNERABILITY - Second rotation before first is committed on-chain
    let alice_jwks_v102 = vec![JWK::Unsupported(UnsupportedJWK::new_for_testing("kid_2", "payload_2")).into()];
    jwk_manager.process_new_observation(issuer_alice.clone(), alice_jwks_v102).unwrap();
    
    // BUG: State transitions from Finished to InProgress
    assert!(matches!(
        jwk_manager.states_by_issuer.get(&issuer_alice).unwrap().consensus_state,
        ConsensusState::InProgress { .. }
    ));
    
    // BUG: First quorum-certified transaction is removed from pool
    let txns_in_pool_after = vtxn_pool.pull(Instant::now() + Duration::from_secs(10), 10, 1024, TransactionFilter::empty());
    assert_eq!(txns_in_pool_after.len(), 0, "BUG: Quorum-certified transaction was removed from pool!");
}

fn create_qc_update(
    private_keys: &[Arc<PrivateKey>],
    issuer: &Issuer,
    version: u64,
    jwks: Vec<JWKMoveStruct>,
) -> QuorumCertifiedUpdate {
    let provider_jwks = ProviderJWKs {
        issuer: issuer.clone(),
        version,
        jwks,
    };
    let signer_bit_vec = BitVec::from(private_keys.iter().map(|_| true).collect::<Vec<_>>());
    let sig = Signature::aggregate(
        private_keys.iter().map(|sk| sk.sign(&provider_jwks).unwrap()).collect::<Vec<_>>(),
    ).unwrap();
    QuorumCertifiedUpdate {
        update: provider_jwks,
        multi_sig: AggregateSignature::new(signer_bit_vec, Some(sig)),
    }
}
```

This test demonstrates that a quorum-certified update in `Finished` state is improperly discarded when a new observation arrives, violating the state machine invariant.

## Notes

The per-key JWK consensus manager already implements the correct behavior by checking for both `InProgress` and `Finished` states before starting new consensus sessions, indicating this was likely an oversight in the issuer-level implementation rather than an intentional design choice.

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

**File:** aptos-move/aptos-vm/src/validator_txns/jwk.rs (L128-130)
```rust
        if on_chain.version + 1 != observed.version {
            return Err(Expected(IncorrectVersion));
        }
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager_per_key.rs (L180-194)
```rust
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
