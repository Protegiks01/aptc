# Audit Report

## Title
JWK Consensus State Inconsistency via Race Condition in Quorum Certificate Processing

## Summary
The `process_quorum_certified_update()` function in the per-key JWK consensus manager accepts quorum certified updates without verifying they match the validator's local proposal. This, combined with a race condition during consensus state replacement, allows validators to accept mismatched quorum certificates, causing consensus drift where different validators certify different JWK updates for the same key.

## Finding Description

The vulnerability exists in the state transition logic at [1](#0-0) 

When a quorum certified update is received, the code transitions from `InProgress` to `Finished` state without verifying that the certified update's content matches the `my_proposal` that was originally initiated. The only check is that the state is `InProgress`, but not whether the quorum certificate is for the correct proposal.

**Attack Scenario:**

1. A validator observes JWK update X for key K=(issuer, kid) and starts consensus, creating state `InProgress{my_proposal: X}` [2](#0-1) 

2. The reliable broadcast task RB_X is spawned and begins collecting signatures from other validators [3](#0-2) 

3. The validator observes a different JWK update Y for the same key K (this can happen legitimately during OIDC provider key rotation, or be caused by Byzantine validators providing conflicting observations)

4. The `maybe_start_consensus()` function checks if consensus is already running [4](#0-3) 

5. Since `X.to_upsert != Y.to_upsert`, the check returns `false`, so the function proceeds to start new consensus for Y

6. The state map is updated via `insert()`, **replacing** the old `InProgress{my_proposal: X}` with `InProgress{my_proposal: Y}` [2](#0-1) 

7. When the old state is dropped, the `QuorumCertProcessGuard` is dropped, triggering `abort()` on the RB_X task [5](#0-4) 

8. **RACE CONDITION**: If RB_X's reliable broadcast has already completed (the `.await` on line 68 of update_certifier.rs has returned), the subsequent synchronous code will execute despite the abort, pushing QC(X) to the channel [6](#0-5) 

9. The event loop receives QC(X), extracts the session key (issuer, kid), and looks up the current state, finding `InProgress{my_proposal: Y}` [7](#0-6) 

10. The code transitions to `Finished{my_proposal: Y, quorum_certified: QC(X)}` **without checking that QC(X) matches Y**

11. A `ValidatorTransaction` is created with QC(X) and submitted to the pool [8](#0-7) 

**Result**: The validator's local state claims it proposed Y, but it's actually submitting a transaction certifying X. Different validators experiencing different observation orderings will accept different quorum certificates for the same key, causing consensus drift at the JWK consensus layer.

Byzantine validators can amplify this vulnerability by:
- Signing multiple conflicting observations quickly to expand the race window
- Providing different observations to different honest validators
- Timing their responses strategically to maximize the probability of the race condition

The reliable broadcast aggregation logic only accepts signatures matching the local view [9](#0-8) , but this doesn't prevent the race condition since each reliable broadcast instance runs independently with its own local view.

## Impact Explanation

This vulnerability constitutes a **High Severity** issue under the "Significant protocol violations" category.

**Broken Invariants:**
- **Consensus Safety** (Invariant #2): The JWK consensus protocol should ensure all honest validators agree on certified updates, but this bug allows them to diverge
- **State Consistency** (Invariant #4): Validators' local consensus states become inconsistent with their submitted transactions

**Impact:**
1. **Consensus Drift**: Different validators accept and believe they certified different JWK updates for the same key
2. **Protocol Integrity**: The off-chain JWK consensus protocol's safety guarantees are violated
3. **State Confusion**: Validators may have incorrect beliefs about what should be on-chain, potentially causing liveness issues
4. **Manual Intervention**: Resolving state inconsistencies may require validator coordination or manual intervention

While the on-chain validation [10](#0-9)  prevents multiple conflicting updates from being applied (version check ensures linearity), the JWK consensus layer itself has diverged, which is a significant protocol violation.

## Likelihood Explanation

**Likelihood: Medium-High**

The vulnerability is exploitable under realistic conditions:

1. **Natural Occurrence**: OIDC providers legitimately rotate keys, causing different validators to observe different JWK states at different times when they query the provider's endpoint

2. **Race Window**: The race condition window exists between when a reliable broadcast task completes and when the abort signal takes effect. With asynchronous task scheduling, this window is non-negligible

3. **Byzantine Amplification**: Byzantine validators (< 1/3 of stake) can:
   - Sign multiple conflicting observations
   - Respond quickly to expand the race window  
   - Provide different observations to different honest validators

4. **No Special Privileges Required**: The attack doesn't require compromising honest validators' keys or gaining insider access

5. **Frequent Observations**: The JWK observation threads query OIDC providers periodically (every 10 seconds per [11](#0-10) ), increasing opportunities for the race to occur

## Recommendation

Add verification that the quorum certified update matches the local proposal before accepting it:

```rust
pub fn process_quorum_certified_update(
    &mut self,
    issuer_level_repr: QuorumCertifiedUpdate,
) -> Result<()> {
    let key_level_update =
        KeyLevelUpdate::try_from_issuer_level_repr(&issuer_level_repr.update)
            .context("process_quorum_certified_update failed with repr err")?;
    let issuer = &key_level_update.issuer;
    let kid = &key_level_update.kid;
    
    let state = self
        .states_by_key
        .entry((issuer.clone(), kid.clone()))
        .or_default();
    
    match state {
        ConsensusState::InProgress { my_proposal, .. } => {
            // ADD THIS VERIFICATION:
            if my_proposal.observed != key_level_update {
                return Err(anyhow!(
                    "Quorum certified update does not match local proposal for issuer {:?} kid {:?}",
                    String::from_utf8(issuer.clone()),
                    String::from_utf8(kid.clone())
                ));
            }
            
            let topic = Topic::JWK_CONSENSUS_PER_KEY_MODE {
                issuer: issuer.clone(),
                kid: kid.clone(),
            };
            let txn = ValidatorTransaction::ObservedJWKUpdate(issuer_level_repr.clone());
            let vtxn_guard = self.vtxn_pool.put(topic, Arc::new(txn), None);
            *state = ConsensusState::Finished {
                vtxn_guard,
                my_proposal: my_proposal.clone(),
                quorum_certified: issuer_level_repr,
            };
            Ok(())
        },
        _ => Err(anyhow!(
            "qc update not expected for issuer {:?} in state {}",
            String::from_utf8(issuer.clone()),
            state.name()
        )),
    }
}
```

**Additional Hardening**: Consider using a channel that delivers the abort signal synchronously before dropping the guard, or tracking expected QC content in the state to reject mismatched certificates.

## Proof of Concept

```rust
#[cfg(test)]
mod consensus_drift_test {
    use super::*;
    use aptos_types::jwks::{JWK, rsa::RSA_JWK};
    
    #[tokio::test]
    async fn test_race_condition_causes_mismatched_qc_acceptance() {
        // Setup: Create a KeyLevelConsensusManager with test epoch state
        let mut manager = create_test_manager();
        
        // Step 1: Validator observes JWK update X for key (issuer, kid)
        let issuer = b"https://accounts.google.com".to_vec();
        let kid = b"key1".to_vec();
        let jwk_x = JWK::RSA(RSA_JWK::new_256_aqab(&kid, "modulus_x"));
        let update_x = KeyLevelUpdate {
            issuer: issuer.clone(),
            base_version: 0,
            kid: kid.clone(),
            to_upsert: Some(jwk_x.clone()),
        };
        
        // Start consensus for X - this creates InProgress state with my_proposal=X
        manager.process_new_observation(issuer.clone(), vec![jwk_x.clone()]).unwrap();
        
        // Verify state is InProgress with proposal X
        let state = manager.states_by_key.get(&(issuer.clone(), kid.clone())).unwrap();
        assert!(matches!(state, ConsensusState::InProgress { my_proposal, .. } 
            if my_proposal.observed.to_upsert == Some(jwk_x.clone())));
        
        // Step 2: Simulate race - reliable broadcast for X completes and creates QC(X)
        // but before it's processed, a new observation Y arrives
        let jwk_y = JWK::RSA(RSA_JWK::new_256_aqab(&kid, "modulus_y")); // Different modulus!
        
        // Step 3: New observation arrives, triggering state replacement
        manager.process_new_observation(issuer.clone(), vec![jwk_y.clone()]).unwrap();
        
        // Verify state is now InProgress with proposal Y (X was replaced)
        let state = manager.states_by_key.get(&(issuer.clone(), kid.clone())).unwrap();
        assert!(matches!(state, ConsensusState::InProgress { my_proposal, .. } 
            if my_proposal.observed.to_upsert == Some(jwk_y.clone())));
        
        // Step 4: The old QC(X) arrives through the channel (race condition)
        let qc_x = create_mock_quorum_cert(update_x);
        
        // Step 5: Process the mismatched QC - THIS SHOULD FAIL BUT DOESN'T
        let result = manager.process_quorum_certified_update(qc_x.clone());
        
        // BUG: The function accepts QC(X) even though my_proposal is Y
        assert!(result.is_ok(), "Function should fail but accepts mismatched QC!");
        
        // Step 6: Verify the inconsistent state
        let state = manager.states_by_key.get(&(issuer.clone(), kid.clone())).unwrap();
        if let ConsensusState::Finished { my_proposal, quorum_certified, .. } = state {
            // VULNERABILITY: my_proposal says Y but quorum_certified contains X
            assert_eq!(my_proposal.observed.to_upsert, Some(jwk_y)); // Proposed Y
            let qc_update = KeyLevelUpdate::try_from_issuer_level_repr(&quorum_certified.update).unwrap();
            assert_eq!(qc_update.to_upsert, Some(jwk_x)); // But certified X
            
            println!("CONSENSUS DRIFT DETECTED:");
            println!("  Validator believes it proposed: {:?}", my_proposal.observed.to_upsert);
            println!("  But actually certified and will submit: {:?}", qc_update.to_upsert);
        }
    }
}
```

This PoC demonstrates the core vulnerability: a validator ends up in state `Finished{my_proposal: Y, quorum_certified: QC(X)}` where the proposal and certified update don't match, creating consensus drift.

### Citations

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

**File:** crates/aptos-jwk-consensus/src/jwk_manager_per_key.rs (L216-228)
```rust
        self.states_by_key.insert(
            (update.issuer.clone(), update.kid.clone()),
            ConsensusState::InProgress {
                my_proposal: ObservedKeyLevelUpdate {
                    author: self.my_addr,
                    observed: update,
                    signature,
                },
                abort_handle_wrapper: QuorumCertProcessGuard {
                    handle: abort_handle,
                },
            },
        );
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager_per_key.rs (L330-346)
```rust
        let state = self
            .states_by_key
            .entry((issuer.clone(), kid.clone()))
            .or_default();
        match state {
            ConsensusState::InProgress { my_proposal, .. } => {
                let topic = Topic::JWK_CONSENSUS_PER_KEY_MODE {
                    issuer: issuer.clone(),
                    kid: kid.clone(),
                };
                let txn = ValidatorTransaction::ObservedJWKUpdate(issuer_level_repr.clone());
                let vtxn_guard = self.vtxn_pool.put(topic, Arc::new(txn), None);
                *state = ConsensusState::Finished {
                    vtxn_guard,
                    my_proposal: my_proposal.clone(),
                    quorum_certified: issuer_level_repr,
                };
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager_per_key.rs (L399-399)
```rust
                        Duration::from_secs(10),
```

**File:** crates/aptos-jwk-consensus/src/update_certifier.rs (L67-82)
```rust
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
```

**File:** crates/aptos-jwk-consensus/src/types.rs (L96-100)
```rust
impl Drop for QuorumCertProcessGuard {
    fn drop(&mut self) {
        let QuorumCertProcessGuard { handle } = self;
        handle.abort();
    }
```

**File:** crates/aptos-jwk-consensus/src/observation_aggregation/mod.rs (L81-84)
```rust
        ensure!(
            self.local_view == peer_view,
            "adding peer observation failed with mismatched view"
        );
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
