# Audit Report

## Title
Race Condition in JWK Consensus Update Certification Allows Stale Observations to Override Current Data

## Summary
A race condition exists in the JWK consensus `start_produce()` function where multiple rapid broadcast tasks can be spawned for the same issuer with different payloads. When an older broadcast completes after a newer one has started but before being fully cancelled, it can push its result to the shared channel and cause the newer broadcast's result to be rejected, leading to stale JWK data being committed on-chain.

## Finding Description

The vulnerability occurs in the interaction between multiple calls to `start_produce()` and the asynchronous task cancellation mechanism. [1](#0-0) 

When observations arrive rapidly, the following sequence can occur:

1. **Broadcast B1 starts** for payload P1 (e.g., JWKs = [key1, key2]) [2](#0-1) 

2. **B1 is actively broadcasting** via reliable broadcast, collecting validator signatures

3. **New observation arrives** with payload P2 (e.g., JWKs = [key1, key3])

4. **`process_new_observation` is called again**, replacing the state and dropping the old `QuorumCertProcessGuard` [3](#0-2) 

5. **Critical race window**: B1's task may have already completed `rb.broadcast()` and obtained QC1, but hasn't been cancelled yet. The task then executes the synchronous code after the await point, pushing QC1 to the channel.

6. **B1 pushes QC1** to `qc_update_tx` (the channel is shared between all broadcasts for the same issuer)

7. **Manager processes QC1**, transitions state to `Finished`, and places the transaction in the validator pool [4](#0-3) 

8. **B2 completes** and attempts to push QC2, but when the manager tries to process it, the state is already `Finished`, causing rejection with error: "qc update not expected for issuer in state Finished"

9. **Result**: QC1 (stale observation) remains in the validator transaction pool and will be committed on-chain, while QC2 (current observation) is discarded.

The channel uses `QueueStyle::KLAST` with capacity 1: [5](#0-4) 

The validator transaction pool ensures only one transaction per topic, but the first one to complete wins: [6](#0-5) 

## Impact Explanation

This issue qualifies as **Medium Severity** under the Aptos bug bounty criteria: "State inconsistencies requiring intervention."

**Security Impact:**
- Stale JWK data could be committed on-chain instead of current observations
- If a cryptographic key was compromised and removed in the newer observation (P2), but the older observation (P1) still contains it, the compromised key would remain valid on-chain
- Authentication/authorization systems relying on on-chain JWKs would use outdated key material
- The inconsistency persists until the next successful observation cycle

**Why Not Higher Severity:**
- Does not directly break blockchain consensus (all validators agree on the committed state)
- Does not cause fund loss or theft
- Does not cause permanent network failure
- System eventually converges when new observations trigger subsequent consensus rounds

## Likelihood Explanation

**Medium-to-High Likelihood** in production environments:

**Triggering Conditions:**
- OIDC provider endpoints that update JWKs frequently or return inconsistent results
- Network latency variations causing observation timing differences
- High validator participation enabling fast quorum formation
- Multiple JWK observers polling the same issuer simultaneously

**Attack Scenarios:**
1. **Malicious OIDC Provider**: An attacker controlling an OIDC provider could deliberately serve different JWKs on rapid requests to trigger the race
2. **Network Manipulation**: Adversary delays observation responses to create timing windows
3. **Natural Occurrence**: Legitimate key rotations happening during observation intervals

The race window exists between the completion of `rb.broadcast().await` and the execution of `qc_update_tx.push()`, which in async Rust runs synchronously without yield points, creating a non-trivial exploitation window.

## Recommendation

**Solution: Add sequence numbering or version checking to reject outdated broadcasts**

Modify the broadcast task to check if it's still relevant before pushing to the channel:

```rust
// In update_certifier.rs, modify start_produce():
let task = async move {
    let qc_update = rb.broadcast(req, agg_state).await.expect("cannot fail");
    ConsensusMode::log_certify_done(epoch, &qc_update);
    let session_key = ConsensusMode::session_key_from_qc(&qc_update);
    
    // NEW: Check if we're still the active consensus before pushing
    // This requires passing a shared state or version counter
    match session_key {
        Ok(key) => {
            // Only push if this broadcast is still relevant
            // Implementation would need state tracking
            let _ = qc_update_tx.push(key, qc_update);
        },
        Err(e) => {
            error!("JWK update QCed but could not identify the session key: {e}");
        },
    }
};
```

**Alternative Solution: Modify the manager to accept newer broadcasts even in Finished state**

In `process_quorum_certified_update`, check if the incoming QC has a higher version or more recent timestamp than the current state, and allow the replacement:

```rust
match &state.consensus_state {
    ConsensusState::InProgress { my_proposal, .. } => {
        // existing logic
    },
    ConsensusState::Finished { quorum_certified: old_qc, .. } => {
        // NEW: If new QC is for a different/newer observation, replace it
        if update.update.version > old_qc.update.version 
           || update.update != old_qc.update {
            // Replace the finished state with the new QC
            let txn = ValidatorTransaction::ObservedJWKUpdate(update.clone());
            let vtxn_guard = self.vtxn_pool.put(...);
            state.consensus_state = ConsensusState::Finished { ... };
        }
    },
    _ => return Err(...),
}
```

## Proof of Concept

```rust
// Reproduction test for the race condition
#[tokio::test]
async fn test_concurrent_start_produce_race() {
    use crate::update_certifier::{TUpdateCertifier, UpdateCertifier};
    use aptos_types::jwks::ProviderJWKs;
    
    // Setup: Create update certifier and channel
    let (qc_tx, mut qc_rx) = aptos_channel::new(QueueStyle::KLAST, 1, None);
    let certifier = /* initialize UpdateCertifier */;
    let epoch_state = /* initialize EpochState */;
    
    // Observation 1: [key1, key2]
    let payload1 = ProviderJWKs {
        issuer: b"google".to_vec(),
        version: 1,
        jwks: vec![/* key1, key2 */],
    };
    
    // Observation 2: [key1, key3] (key2 removed, key3 added)
    let payload2 = ProviderJWKs {
        issuer: b"google".to_vec(),
        version: 1, // SAME VERSION - this is the issue
        jwks: vec![/* key1, key3 */],
    };
    
    // Start broadcast 1
    let handle1 = certifier.start_produce(epoch_state.clone(), payload1, qc_tx.clone())?;
    
    // Simulate some progress in broadcast 1
    tokio::time::sleep(Duration::from_millis(50)).await;
    
    // Start broadcast 2 (this will try to abort broadcast 1)
    let handle2 = certifier.start_produce(epoch_state.clone(), payload2, qc_tx.clone())?;
    
    // Drop handle1 to abort broadcast 1
    drop(handle1);
    
    // Wait for broadcasts to complete
    tokio::time::sleep(Duration::from_millis(200)).await;
    
    // Receive QC updates
    let qc1 = qc_rx.next().await;
    let qc2 = qc_rx.next().await;
    
    // EXPECTED: Only QC2 should be received (newer observation)
    // ACTUAL BUG: QC1 might be received if it completed before abort took effect
    
    assert!(qc1.is_some());
    // This assertion may fail due to the race condition:
    assert_eq!(qc1.unwrap().update.jwks, payload2.jwks, 
               "Stale observation QC was processed instead of current one");
}
```

**Notes**

The vulnerability stems from the fundamental design where:
1. Abort mechanisms in async Rust are cooperative (only cancel at await points)
2. Multiple broadcasts can be initiated for the same issuer without proper sequencing
3. The channel and state management don't enforce ordering guarantees

This race is exacerbated by the `KLAST` queue style which drops older messages - if timing allows the stale QC to be processed first, the newer QC gets dropped when it arrives later, inverting the intended priority.

### Citations

**File:** crates/aptos-jwk-consensus/src/update_certifier.rs (L67-83)
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
    }
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager/mod.rs (L72-72)
```rust
        let (qc_update_tx, qc_update_rx) = aptos_channel::new(QueueStyle::KLAST, 1, None);
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager/mod.rs (L206-223)
```rust
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

**File:** crates/aptos-jwk-consensus/src/types.rs (L96-101)
```rust
impl Drop for QuorumCertProcessGuard {
    fn drop(&mut self) {
        let QuorumCertProcessGuard { handle } = self;
        handle.abort();
    }
}
```

**File:** crates/validator-transaction-pool/src/lib.rs (L74-76)
```rust
        if let Some(old_seq_num) = pool.seq_nums_by_topic.insert(topic.clone(), seq_num) {
            pool.txn_queue.remove(&old_seq_num);
        }
```
