# Audit Report

## Title
Race Condition in JWK Consensus Allows Acceptance of Stale Quorum Certificates Leading to On-Chain State Inconsistency

## Summary
A race condition exists in `KeyLevelConsensusManager` between concurrent certifier task completion and sequential state updates. The system lacks validation to ensure received quorum certificates match the current consensus proposal, allowing stale JWK values to be committed on-chain during rapid key rotations.

## Finding Description

The vulnerability occurs due to insufficient synchronization between concurrent `UpdateCertifier` tasks and the `KeyLevelConsensusManager` event loop in the JWK consensus system.

**Race Condition Mechanics:**

When `maybe_start_consensus()` initiates consensus for a new JWK update, it inserts an `InProgress` state with a `QuorumCertProcessGuard`. If a second observation arrives with a different JWK value before the first certifier completes, the state is overwritten, dropping the old guard. [1](#0-0) 

When the guard is dropped, it calls `abort()` on the certifier task: [2](#0-1) 

However, the certifier task runs concurrently and may have already pushed its quorum certificate to the channel before the abort occurs: [3](#0-2) 

**Critical Missing Validation:**

The `process_quorum_certified_update()` function only verifies the state is `InProgress` but does NOT validate that the received quorum certificate matches the current `my_proposal.observed`: [4](#0-3) 

This allows a quorum certificate for value A to be accepted when the current state expects value B, violating consensus integrity.

**Attack Scenario:**
1. Observation arrives with JWK value A → starts certifier_A → inserts InProgress_A
2. Certifier_A completes, pushes QC_A to channel
3. Before event loop processes QC_A, observation with value B arrives → overwrites to InProgress_B
4. Event loop receives QC_A, finds InProgress_B, accepts QC_A anyway (missing validation)
5. System commits QC_A to validator transaction pool despite current value being B

## Impact Explanation

This vulnerability qualifies as **Medium Severity** per Aptos bug bounty criteria:

**State Inconsistencies Requiring Intervention:** The validator's internal state (`my_proposal`) references value B while the committed quorum certificate (`quorum_certified`) contains value A. The wrong JWK value is submitted to the validator transaction pool and can be committed on-chain. [5](#0-4) 

**Authentication/Authorization Impact:** JWKs validate JWTs from OIDC providers for keyless accounts. A stale JWK on-chain causes:
- Legitimate authentication attempts with the current key to fail
- Potential acceptance of JWTs signed with stale keys that should be rejected

**Consensus State Integrity:** Multiple validators experiencing this race during the same key rotation could reach consensus on the wrong JWK value, creating persistent on-chain inconsistency.

The KLAST channel configuration provides partial protection but cannot prevent the race if the stale QC is processed before the new certifier completes: [6](#0-5) 

## Likelihood Explanation

**Likelihood: Medium**

The race window is narrow (microseconds to milliseconds) but can occur naturally during:
- OIDC provider rapid key rotations
- Provider endpoints returning inconsistent values during propagation
- Network timing variations across validators

The JWK observer polls every 10 seconds: [7](#0-6) 

While attackers cannot directly control OIDC provider responses, the race occurs naturally during legitimate key rotations, especially when providers have eventual consistency issues or perform rapid rotations.

## Recommendation

Add validation in `process_quorum_certified_update()` to verify the received quorum certificate matches the current proposal before accepting it:

```rust
ConsensusState::InProgress { my_proposal, .. } => {
    // Validate QC matches current proposal
    if my_proposal.observed != key_level_update {
        return Err(anyhow!(
            "Received QC doesn't match current proposal for issuer {:?} kid {:?}",
            String::from_utf8(issuer.clone()),
            String::from_utf8(kid.clone())
        ));
    }
    
    let topic = Topic::JWK_CONSENSUS_PER_KEY_MODE {
        issuer: issuer.clone(),
        kid: kid.clone(),
    };
    // ... rest of the logic
}
```

This ensures stale quorum certificates are rejected, maintaining consistency between the validator's proposal and the committed update.

## Proof of Concept

While a full PoC requires complex integration testing with concurrent tasks and precise timing, the vulnerability is demonstrable through code analysis:

1. The concurrent task structure in `update_certifier.rs` allows completion before abort
2. The missing validation in `process_quorum_certified_update()` is verifiable by inspection
3. The state overwrite behavior at line 216 is confirmed in the implementation
4. Test coverage in `jwk_manager/tests.rs` does not cover this race condition scenario [8](#0-7) 

The test demonstrates state overwriting when a new observation arrives during in-progress consensus, but does not test what happens when the old certifier has already pushed its QC to the channel.

### Citations

**File:** crates/aptos-jwk-consensus/src/jwk_manager_per_key.rs (L79-79)
```rust
        let (qc_update_tx, qc_update_rx) = aptos_channel::new(QueueStyle::KLAST, 1, None);
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

**File:** crates/aptos-jwk-consensus/src/jwk_manager_per_key.rs (L335-354)
```rust
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
                info!(
                    epoch = self.epoch_state.epoch,
                    issuer = issuer_str,
                    kid = kid_str,
                    base_version = key_level_update.base_version,
                    "certified key-level update accepted."
                );
                Ok(())
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager_per_key.rs (L399-399)
```rust
                        Duration::from_secs(10),
```

**File:** crates/aptos-jwk-consensus/src/types.rs (L96-100)
```rust
impl Drop for QuorumCertProcessGuard {
    fn drop(&mut self) {
        let QuorumCertProcessGuard { handle } = self;
        handle.abort();
    }
```

**File:** crates/aptos-jwk-consensus/src/update_certifier.rs (L67-79)
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
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager/tests.rs (L272-306)
```rust
    // If Alice rotates again while the consensus session for Alice is in progress, the existing session should be discarded and a new session should start.
    let alice_jwks_new_2 = vec![
        JWK::Unsupported(UnsupportedJWK::new_for_testing(
            "alice_jwk_id_1",
            "jwk_payload_1",
        ))
        .into(),
        JWK::Unsupported(UnsupportedJWK::new_for_testing(
            "alice_jwk_id_3",
            "jwk_payload_5",
        ))
        .into(),
    ];
    assert!(jwk_manager
        .process_new_observation(issuer_alice.clone(), alice_jwks_new_2.clone())
        .is_ok());
    {
        let expected_alice_state = expected_states.get_mut(&issuer_alice).unwrap();
        expected_alice_state.observed = Some(alice_jwks_new_2.clone());
        let observed = ProviderJWKs {
            issuer: issuer_alice.clone(),
            version: 112,
            jwks: alice_jwks_new_2.clone(),
        };
        let signature = private_keys[0].sign(&observed).unwrap();
        expected_alice_state.consensus_state = ConsensusState::InProgress {
            my_proposal: ObservedUpdate {
                author: addrs[0],
                observed,
                signature,
            },
            abort_handle_wrapper: QuorumCertProcessGuard::dummy(),
        };
    }
    assert_eq!(expected_states, jwk_manager.states_by_issuer);
```
