# Audit Report

## Title
Race Condition in JWK Consensus Allows Mismatched Proposal and Quorum Certificate Acceptance

## Summary
The `PerIssuerMode::session_key_from_qc` method extracts the session key without validation, combined with a KLAST queue of size 1 and missing validation in `process_quorum_certified_update()`, allows a validator to accept a Quorum Certified Update (QC) that does not match their current proposal, leading to state inconsistency.

## Finding Description

The JWK consensus system has three interconnected issues that together create a race condition vulnerability:

**Issue 1: Unvalidated Session Key Extraction** [1](#0-0) 

The `session_key_from_qc` method directly clones the issuer without any validation of the QC content.

**Issue 2: KLAST Channel Configuration** [2](#0-1) 

The channel is configured with `QueueStyle::KLAST` and size 1, meaning only the last QC per issuer is kept, and earlier QCs are silently dropped. [3](#0-2) 

The KLAST queue style drops old messages when full.

**Issue 3: Missing Validation in QC Processing** [4](#0-3) 

The `process_quorum_certified_update()` method accepts any QC when the state is `InProgress` without validating that the QC matches the current `my_proposal`.

**Attack Scenario:**

1. Validator observes JWKs for issuer "A" (version 10), creates proposal P1, starts reliable broadcast #1
2. Before #1 completes, validator observes different JWKs for issuer "A" (version 10 with different content), creates proposal P2
3. The new observation replaces the consensus state with P2 and attempts to abort broadcast #1 via the guard [5](#0-4) 

4. However, if broadcast #1 already completed and pushed its QC to the channel before being aborted: [6](#0-5) 

5. The old QC (for P1) remains in the channel while the state shows `InProgress` with P2
6. The event loop processes the QC for P1, but the state now has proposal P2
7. No validation occurs - the QC is accepted and stored: [7](#0-6) 

8. Result: `my_proposal` contains P2, but `quorum_certified` contains QC for P1 - a mismatch

This violates the critical invariant: **"A validator's certified update should match their current proposal when finishing consensus."**

## Impact Explanation

**Medium Severity** - State inconsistencies requiring intervention

This vulnerability causes validators to store conflicting state:
- The local state shows one proposal as finished
- The transaction pool receives a different certified update
- This breaks the assumption that `my_proposal == quorum_certified` in the Finished state

Potential consequences:
1. **State Confusion**: The validator's internal state does not reflect what was actually certified
2. **Monitoring/Debugging Issues**: Operators cannot trust local state for troubleshooting
3. **Cascading Errors**: Other code paths may assume the stored proposal matches the QC, leading to undefined behavior
4. **Unnecessary Re-proposals**: When on-chain state updates, the validator may incorrectly believe they need to re-propose

While this does not directly cause funds loss or consensus safety violations, it creates state inconsistencies that could require manual intervention to resolve, fitting the Medium severity category.

## Likelihood Explanation

**Moderate to High Likelihood**

This can occur naturally without attacker intervention:
- OIDC providers (Google, GitHub, etc.) periodically update their JWKs
- If updates occur in quick succession or network delays cause re-observations
- The race condition between observation processing and QC completion can trigger
- No Byzantine behavior is required - normal operation with timing variations is sufficient

The likelihood increases in scenarios where:
- JWK providers perform rapid key rotations
- Network latency causes observation delays
- Multiple validators trigger observations simultaneously

## Recommendation

Add validation in `process_quorum_certified_update()` to ensure the received QC matches the current proposal:

```rust
pub fn process_quorum_certified_update(&mut self, update: QuorumCertifiedUpdate) -> Result<()> {
    let issuer = update.update.issuer.clone();
    let state = self.states_by_issuer.entry(issuer.clone()).or_default();
    
    match &state.consensus_state {
        ConsensusState::InProgress { my_proposal, .. } => {
            // VALIDATION: Ensure QC matches current proposal
            ensure!(
                update.update == my_proposal.observed,
                "Received QC does not match current proposal for issuer {:?}",
                String::from_utf8(issuer.clone())
            );
            
            let txn = ValidatorTransaction::ObservedJWKUpdate(update.clone());
            let vtxn_guard = self.vtxn_pool.put(
                Topic::JWK_CONSENSUS(issuer.clone()), 
                Arc::new(txn), 
                None
            );
            state.consensus_state = ConsensusState::Finished {
                vtxn_guard,
                my_proposal: my_proposal.clone(),
                quorum_certified: update.clone(),
            };
            Ok(())
        },
        _ => Err(anyhow!("qc update not expected..."))
    }
}
```

Alternative: Consider using a different channel configuration or adding sequence numbers to proposals and QCs to detect stale updates.

## Proof of Concept

```rust
#[tokio::test]
async fn test_qc_proposal_mismatch_race_condition() {
    // Setup: Create consensus manager with mock components
    let (consensus_key, my_addr, epoch_state) = setup_test_validator();
    let (qc_tx, qc_rx) = aptos_channel::new(QueueStyle::KLAST, 1, None);
    
    let issuer = b"test.issuer.com".to_vec();
    
    // Step 1: Observer sees JWKs version 1
    let jwks_v1 = vec![test_jwk("key1", "n1")];
    let proposal_v1 = ProviderJWKs {
        issuer: issuer.clone(),
        version: 1,
        jwks: jwks_v1.clone(),
    };
    
    // Step 2: Start reliable broadcast for v1
    // (Simulate broadcast completing and pushing QC to channel)
    let qc_v1 = QuorumCertifiedUpdate {
        update: proposal_v1.clone(),
        multi_sig: create_test_signature(),
    };
    qc_tx.push(issuer.clone(), qc_v1.clone()).unwrap();
    
    // Step 3: Before QC is consumed, observer sees different JWKs (still version 1)
    let jwks_v1_prime = vec![test_jwk("key1", "n2")]; // Different modulus
    let proposal_v1_prime = ProviderJWKs {
        issuer: issuer.clone(),
        version: 1,
        jwks: jwks_v1_prime.clone(),
    };
    
    // Update state to InProgress with new proposal
    manager.states_by_issuer.insert(
        issuer.clone(),
        PerProviderState {
            consensus_state: ConsensusState::InProgress {
                my_proposal: ObservedUpdate {
                    author: my_addr,
                    observed: proposal_v1_prime.clone(),
                    signature: sign(&proposal_v1_prime),
                },
                abort_handle_wrapper: QuorumCertProcessGuard::dummy(),
            },
            ..Default::default()
        },
    );
    
    // Step 4: Process the old QC from channel
    let qc_from_channel = qc_rx.next().await.unwrap();
    let result = manager.process_quorum_certified_update(qc_from_channel);
    
    // BUG: This should fail but succeeds!
    assert!(result.is_ok());
    
    // Step 5: Verify state mismatch
    let final_state = manager.states_by_issuer.get(&issuer).unwrap();
    match &final_state.consensus_state {
        ConsensusState::Finished { my_proposal, quorum_certified, .. } => {
            // VULNERABILITY: These don't match!
            assert_ne!(my_proposal.observed, quorum_certified.update);
            assert_eq!(my_proposal.observed.jwks, jwks_v1_prime);
            assert_eq!(quorum_certified.update.jwks, jwks_v1);
        },
        _ => panic!("Expected Finished state"),
    }
}
```

## Notes

This vulnerability is rooted in the interaction between three design decisions:
1. Session key extraction without content validation
2. KLAST queue dropping older messages
3. Missing proposal-QC matching validation

While each component may seem reasonable in isolation, their combination creates a race condition that violates state consistency invariants. The fix requires adding explicit validation that received QCs match current proposals before acceptance.

### Citations

**File:** crates/aptos-jwk-consensus/src/mode/per_issuer.rs (L39-41)
```rust
    fn session_key_from_qc(qc: &QuorumCertifiedUpdate) -> anyhow::Result<Issuer> {
        Ok(qc.update.issuer.clone())
    }
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager/mod.rs (L72-72)
```rust
        let (qc_update_tx, qc_update_rx) = aptos_channel::new(QueueStyle::KLAST, 1, None);
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

**File:** crates/channel/src/message_queues.rs (L138-147)
```rust
            match self.queue_style {
                // Drop the newest message for FIFO
                QueueStyle::FIFO => Some(message),
                // Drop the oldest message for LIFO
                QueueStyle::LIFO | QueueStyle::KLAST => {
                    let oldest = key_message_queue.pop_front();
                    key_message_queue.push_back(message);
                    oldest
                },
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
