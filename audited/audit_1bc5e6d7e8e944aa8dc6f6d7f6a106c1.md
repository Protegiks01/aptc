# Audit Report

## Title
JWK Consensus Network Spam via Repeated Observation Restart Without Rate Limiting

## Summary
A malicious validator can repeatedly trigger `process_new_observation()` with different JWK sets for the same issuer, causing unlimited consensus session restarts that spam the validator network with conflicting proposals. The function lacks checks for in-progress consensus and has no rate limiting, allowing a Byzantine validator to overwhelm honest validators with broadcast messages.

## Finding Description

The `process_new_observation()` function in the JWK consensus manager handles new JWK observations from OIDC providers. However, it contains a critical flaw: it unconditionally starts a new consensus session whenever the observed JWKs differ from the on-chain state, **without checking if consensus is already in progress** for that issuer. [1](#0-0) 

The vulnerability manifests through the following code path:

1. **No In-Progress Check**: The function only compares observed JWKs against on-chain state, not against any in-progress consensus proposal.

2. **Unconditional State Overwrite**: When different JWKs are observed, the function immediately overwrites `state.consensus_state` with a new `InProgress` state, even if consensus is already running.

3. **Abort But Messages Already Sent**: The old `QuorumCertProcessGuard` is dropped, which aborts the previous consensus task. However, the abort mechanism in `QuorumCertProcessGuard` only cancels the waiting task, not the already-sent broadcast messages. [2](#0-1) 

4. **Immediate Broadcast**: Each call to `start_produce()` triggers `ReliableBroadcast::broadcast()`, which immediately sends RPC requests to ALL validators in the network. [3](#0-2) [4](#0-3) 

**Attack Scenario:**

A malicious validator running modified software can inject arbitrary observations into their local `observation_tx` channel, bypassing the legitimate `JWKObserver` that fetches from real OIDC providers. For each unique JWK set injected:

1. `process_new_observation()` is called with different JWKs
2. A new consensus session starts via `update_certifier.start_produce()`
3. `ReliableBroadcast::broadcast()` immediately sends observation requests to all N validators
4. The previous consensus is aborted, but messages were already sent
5. Repeat M times → M × N broadcast messages flood the network

**Broken Invariants:**
- **Resource Limits** (Invariant #9): The protocol fails to enforce limits on consensus session creation rate
- **Consensus Liveness**: Honest validators are overwhelmed with processing conflicting proposals, degrading JWK consensus availability

## Impact Explanation

**Severity: High** ($50,000 tier per Aptos Bug Bounty)

This vulnerability falls under **"Validator node slowdowns"** and **"Significant protocol violations"** categories:

1. **Network Resource Exhaustion**: A single malicious validator can generate M different observations, creating M × N RPC messages (where N = number of validators). With 100 validators and 1000 fake observations per second, this produces 100,000 messages/second.

2. **Honest Validator Processing Overhead**: Each honest validator must:
   - Receive and deserialize observation requests
   - Validate signatures
   - Respond with their own signed observations
   - Attempt aggregation (which will fail due to view mismatch)

3. **JWK Consensus Disruption**: The constant churn of consensus sessions for an issuer prevents legitimate JWK updates from completing, as the malicious validator keeps aborting and restarting.

4. **CPU and Memory Pressure**: Signature verification, serialization, and state management for each spurious message consumes validator resources.

The impact stops short of Critical severity because:
- It doesn't directly compromise consensus safety or steal funds
- It requires a malicious validator (insider threat)
- Honest validators can still process other transactions (non-JWK consensus)
- Network-layer rate limiting (if configured) may provide partial mitigation

## Likelihood Explanation

**Likelihood: Medium-High**

**Factors increasing likelihood:**
- The attack requires only a single malicious validator (no collusion needed)
- Byzantine fault tolerance assumes up to 1/3 validators can be malicious, so this threat model is realistic
- The code modification required is trivial (inject observations into a local channel)
- There are NO application-level defenses in the current code
- The attack is persistent and can run continuously

**Factors decreasing likelihood:**
- Requires a validator to run modified node software (insider threat)
- Malicious behavior may be detectable through monitoring (abnormal observation patterns)
- Network-layer rate limiting may partially mitigate (but not prevent) the attack
- Validators have reputational stakes that disincentivize obvious attacks

## Recommendation

Implement multiple defensive layers:

**1. In-Progress Consensus Check:**
```rust
pub fn process_new_observation(
    &mut self,
    issuer: Issuer,
    jwks: Vec<JWKMoveStruct>,
) -> Result<()> {
    let state = self.states_by_issuer.entry(issuer.clone()).or_default();
    state.observed = Some(jwks.clone());
    
    // NEW: Check if consensus is already in progress
    if matches!(state.consensus_state, ConsensusState::InProgress { .. }) {
        // Option A: Ignore new observation if consensus in progress
        debug!("Ignoring observation for {}: consensus already in progress", 
               String::from_utf8_lossy(&issuer));
        return Ok(());
        
        // Option B: Only update if new observation matches in-progress proposal
        // if let ConsensusState::InProgress { my_proposal, .. } = &state.consensus_state {
        //     if my_proposal.observed.jwks != jwks {
        //         return Ok(());  // Ignore conflicting observation
        //     }
        // }
    }
    
    if state.observed.as_ref() != state.on_chain.as_ref().map(ProviderJWKs::jwks) {
        // ... existing consensus start logic
    }
    Ok(())
}
```

**2. Rate Limiting Per Issuer:**
```rust
struct PerProviderState {
    pub on_chain: Option<ProviderJWKs>,
    pub observed: Option<Vec<JWKMoveStruct>>,
    pub consensus_state: ConsensusState<ObservedUpdate>,
    pub last_consensus_start: Option<Instant>,  // NEW
}

// In process_new_observation, before starting consensus:
if let Some(last_start) = state.last_consensus_start {
    let min_interval = Duration::from_secs(10);  // Configurable
    if last_start.elapsed() < min_interval {
        warn!("Rate limit: Cannot start consensus for {} within {}s", 
              String::from_utf8_lossy(&issuer), min_interval.as_secs());
        return Ok(());
    }
}
state.last_consensus_start = Some(Instant::now());
```

**3. Observation Deduplication:**
```rust
// Before starting new consensus, check if observation matches current proposal
if let ConsensusState::InProgress { my_proposal, .. } = &state.consensus_state {
    if my_proposal.observed.jwks == jwks {
        return Ok(());  // Duplicate observation, no action needed
    }
}
```

**4. Network-Layer Rate Limiting:**
Ensure `inbound_rate_limit_config` in `NetworkConfig` is properly configured for JWK consensus RPC endpoints to limit per-peer message rates.

## Proof of Concept

```rust
#[cfg(test)]
mod spam_attack_poc {
    use super::*;
    use aptos_types::jwks::jwk::JWKMoveStruct;
    
    #[tokio::test]
    async fn test_repeated_observation_spam() {
        // Setup: Create JWK manager with test configuration
        let (consensus_key, epoch_state, update_certifier, vtxn_pool) = 
            create_test_components();
        let mut manager = IssuerLevelConsensusManager::new(
            consensus_key,
            AccountAddress::random(),
            epoch_state,
            update_certifier.clone(),
            vtxn_pool,
        );
        
        let issuer = b"https://accounts.google.com".to_vec();
        let mut message_count = 0;
        
        // Attack: Rapidly send 100 different JWK observations for same issuer
        for i in 0..100 {
            let fake_jwks = vec![JWKMoveStruct {
                variant: 0,  // RSA
                kid: format!("key_{}", i).into_bytes(),
                kty: b"RSA".to_vec(),
                alg: b"RS256".to_vec(),
                e: b"AQAB".to_vec(),
                n: vec![i as u8; 256],  // Different for each iteration
            }];
            
            // This should trigger a new consensus session each time
            manager.process_new_observation(issuer.clone(), fake_jwks)
                .expect("observation should succeed");
            
            message_count += 1;
        }
        
        // Verify: Each observation triggered a broadcast
        // In real attack with N validators, this would be 100 * N messages
        let broadcasts_sent = update_certifier.get_broadcast_count();
        assert_eq!(broadcasts_sent, 100, 
            "Expected 100 broadcasts, indicating no rate limiting");
        
        println!("Attack successful: {} consensus sessions started, \
                  {} * N network messages sent", message_count, message_count);
    }
}
```

**To demonstrate in a live network:**
1. Deploy a modified validator node with observation injection capability
2. Inject 1000 different JWK sets for a single issuer over 10 seconds
3. Monitor network traffic showing ~100,000 RPC messages (1000 × 100 validators)
4. Observe CPU/memory spike on honest validators processing these messages
5. Verify JWK consensus for that issuer fails to complete during attack

## Notes

This vulnerability specifically affects the per-issuer JWK consensus mode. The implementation assumes honest behavior from validators' local `JWKObserver` threads, but provides no defense against a Byzantine validator that can inject arbitrary observations. While the observation aggregation layer prevents malicious observations from reaching quorum (due to view mismatch checks), the network damage occurs during the broadcast phase, before aggregation. The fix should be implemented at the observation processing layer to prevent consensus session spam, complemented by network-layer rate limiting for defense in depth.

### Citations

**File:** crates/aptos-jwk-consensus/src/jwk_manager/mod.rs (L194-228)
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
            info!("[JWK] update observed, update={:?}", observed);
        }

        Ok(())
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

**File:** crates/aptos-jwk-consensus/src/update_certifier.rs (L49-84)
```rust
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
}
```

**File:** crates/reliable-broadcast/src/lib.rs (L164-166)
```rust
            for receiver in receivers {
                rpc_futures.push(send_message(receiver, None));
            }
```
