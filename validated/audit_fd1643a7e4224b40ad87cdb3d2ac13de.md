# Audit Report

## Title
JWK Consensus Manager Transaction Pool Removal Vulnerability via Rapid Observation State Transitions

## Summary
The JWK consensus manager unconditionally restarts consensus when new observations arrive, even when a quorum-certified update is already in the validator transaction pool awaiting block inclusion. This causes premature removal of valid transactions through guard drops, enabling denial-of-service attacks on JWK updates by rapidly oscillating provider keys.

## Finding Description

The vulnerability exists in the `process_new_observation()` method of the `IssuerLevelConsensusManager`. The critical flaw occurs when the method checks whether a new observation differs from the on-chain state without verifying the current consensus state. [1](#0-0) 

This check only compares `observed` vs `on_chain`, but does NOT check if consensus has already completed and a transaction is waiting in the pool. When the check passes, the code unconditionally overwrites the consensus state: [2](#0-1) 

When a `Finished` state (which contains a quorum-certified update in the validator transaction pool) is replaced by a new `InProgress` state, the old state is dropped. The `Finished` variant contains a `vtxn_guard` field: [3](#0-2) 

When this guard is dropped, the `TxnGuard::drop()` implementation automatically removes the transaction from the pool: [4](#0-3) 

**Attack Scenario:**
1. OIDC provider publishes JWKs = [key1, key2]
2. Validators observe and reach consensus, obtaining a quorum certificate
3. Quorum-certified update placed in validator transaction pool with state = `Finished`
4. Before the transaction is pulled and executed on-chain, the provider publishes JWKs = [key1, key2, key3]
5. Validators observe the new state at the next polling interval (every 10 seconds)
6. Check at line 196 passes since new observed ≠ on-chain
7. Line 216 overwrites `Finished` with `InProgress`, dropping the `vtxn_guard`
8. Original quorum-certified transaction removed from pool
9. Attacker repeats the rotation to prevent any update from succeeding

The timing window exists because JWK observations occur every 10 seconds: [5](#0-4) 

This creates a window between consensus completion and on-chain execution where new observations can trigger the vulnerability.

## Impact Explanation

This constitutes **Medium Severity** under Aptos bug bounty criteria as a **Limited Protocol Violation**:

1. **Protocol Subsystem Disruption**: JWK consensus is a validator operation for on-chain authentication. While not affecting core AptosBFT consensus, blocking JWK updates prevents proper OIDC integration for that specific provider.

2. **Temporary Liveness Failure**: Causes persistent failure of JWK update subsystem for the affected provider, requiring manual intervention (governance removal of malicious provider) to resolve.

3. **Resource Waste**: Validators expend computational resources performing consensus that never materializes on-chain, though this does not significantly degrade main consensus performance.

4. **Limited Scope**: The vulnerability affects only the JWK consensus subsystem for a specific provider. Core blockchain consensus (AptosBFT), fund security, and network liveness remain unaffected. No funds are at risk.

This does NOT reach High severity because it does not cause "significant performance degradation affecting [main] consensus" or network-wide validator slowdowns. The impact is isolated to the JWK consensus subsystem.

## Likelihood Explanation

**Likelihood: Medium**

This vulnerability can be triggered under the following conditions:

1. **Timing Window**: The 10-second observation interval combined with typical block production times (few seconds) creates a real window of opportunity between consensus completion and on-chain execution.

2. **Attacker Requirements**: Requires control over an OIDC provider's JWK endpoint. This could occur through:
   - Operating a malicious OIDC provider added via governance
   - Compromising an existing supported OIDC provider's infrastructure
   - Legitimate providers with misconfigured or unstable key rotation

3. **Triggering Mechanism**: Can be triggered by publishing key set A, waiting for partial consensus, then publishing key set B before on-chain commitment. This pattern can be repeated indefinitely.

4. **Natural Occurrence**: Could also occur accidentally with legitimate rapid key rotations during security incidents.

The attack barrier includes needing OIDC provider access and having that provider in the governance-approved list, which provides some protection but does not eliminate the risk from compromised or malicious providers.

## Recommendation

Add a check in `process_new_observation()` to prevent overwriting a `Finished` state:

```rust
pub fn process_new_observation(
    &mut self,
    issuer: Issuer,
    jwks: Vec<JWKMoveStruct>,
) -> Result<()> {
    let state = self.states_by_issuer.entry(issuer.clone()).or_default();
    state.observed = Some(jwks.clone());
    
    // Check if consensus is already finished with a transaction in the pool
    if matches!(state.consensus_state, ConsensusState::Finished { .. }) {
        // Don't restart consensus if we already have a QC in the pool
        // The on-chain state update will reset this via reset_with_on_chain_state
        debug!("Consensus already finished, ignoring new observation until on-chain update");
        return Ok(());
    }
    
    if state.observed.as_ref() != state.on_chain.as_ref().map(ProviderJWKs::jwks) {
        // existing logic to start consensus
        ...
    }
    Ok(())
}
```

Alternatively, only restart consensus if the new observation is sufficiently different or after a minimum time delay.

## Proof of Concept

The existing test suite demonstrates state transitions but does not test the specific case of overwriting a `Finished` state. The test at lines 272-306 shows replacing `InProgress` with `InProgress`, but not `Finished` with `InProgress`: [6](#0-5) 

A proof-of-concept test would simulate:
1. Completing consensus and transitioning to `Finished` state
2. Calling `process_new_observation()` with different JWKs before on-chain update
3. Verifying the transaction was removed from the validator transaction pool

The vulnerability is confirmed by code inspection showing the unconditional state overwrite without checking for `Finished` status.

### Citations

**File:** crates/aptos-jwk-consensus/src/jwk_manager/mod.rs (L122-122)
```rust
                        Duration::from_secs(10),
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager/mod.rs (L196-196)
```rust
        if state.observed.as_ref() != state.on_chain.as_ref().map(ProviderJWKs::jwks) {
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager/mod.rs (L216-223)
```rust
            state.consensus_state = ConsensusState::InProgress {
                my_proposal: ObservedUpdate {
                    author: self.my_addr,
                    observed: observed.clone(),
                    signature,
                },
                abort_handle_wrapper: QuorumCertProcessGuard::new(abort_handle),
            };
```

**File:** crates/aptos-jwk-consensus/src/types.rs (L110-114)
```rust
    Finished {
        vtxn_guard: TxnGuard,
        my_proposal: T,
        quorum_certified: QuorumCertifiedUpdate,
    },
```

**File:** crates/validator-transaction-pool/src/lib.rs (L202-206)
```rust
impl Drop for TxnGuard {
    fn drop(&mut self) {
        self.pool.lock().try_delete(self.seq_num);
    }
}
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
