# Audit Report

## Title
Race Condition in JWK Consensus Allows Mismatched Proposal and Quorum Certificate Acceptance

## Summary
The JWK consensus system contains a race condition where a validator can accept a Quorum Certified Update (QC) that does not match their current proposal. This occurs due to missing validation in `process_quorum_certified_update()`, combined with the abort mechanism timing and KLAST channel configuration, leading to state inconsistency between `my_proposal` and `quorum_certified` in the Finished state.

## Finding Description

The JWK consensus system has three interconnected components that together enable a race condition vulnerability:

**Issue 1: Unvalidated Session Key Extraction**

The `session_key_from_qc` method extracts the session key (issuer) without any validation of the QC content itself. [1](#0-0) 

While this method is designed for routing purposes, it demonstrates that session key extraction does not perform QC validation.

**Issue 2: KLAST Channel Configuration**

The quorum certified update channel is configured with `QueueStyle::KLAST` and size 1. [2](#0-1) 

KLAST queue style drops the oldest messages when the queue is full, keeping only the most recent message per key. [3](#0-2) 

**Issue 3: Missing Validation in QC Processing**

The critical vulnerability is in `process_quorum_certified_update()`, which accepts any QC when the consensus state is `InProgress` without validating that the QC matches the current `my_proposal`. [4](#0-3) 

The method transitions directly to the Finished state, storing the received QC alongside the existing `my_proposal`, without checking if they match.

**Race Condition Scenario:**

1. Validator observes JWKs for an issuer, creates proposal P1 (version N+1, content C1), starts reliable broadcast #1
2. JWKObserver fetches again and receives different JWKs, creates proposal P2 (version N+1, content C2) [5](#0-4) 
3. The new observation updates consensus state to InProgress with P2 and stores a new abort handle [6](#0-5) 
4. The old QuorumCertProcessGuard is dropped, attempting to abort broadcast #1 [7](#0-6) 
5. However, if broadcast #1 already completed and pushed its QC to the channel before the abort signal was processed [8](#0-7) 
6. The event loop processes the QC for P1 while the state contains proposal P2
7. `process_quorum_certified_update()` accepts the QC for P1 without validation, creating a Finished state where `my_proposal` points to P2 but `quorum_certified` contains the QC for P1

This violates the invariant that a validator's certified update should match their current proposal when finishing consensus.

## Impact Explanation

**Medium Severity** - State inconsistencies requiring manual intervention

This vulnerability causes validators to store conflicting internal state, meeting the Medium severity criteria per the Aptos bug bounty program (state inconsistencies requiring intervention). The specific impacts are:

1. **State Confusion**: The validator's `Finished` state contains `my_proposal` with one set of JWKs (P2) while `quorum_certified` contains a QC for different JWKs (P1)
2. **Monitoring/Debugging Issues**: Operators inspecting the validator's local state will see inconsistencies that make troubleshooting difficult
3. **Potential Re-proposal Loops**: When the on-chain state updates with P1, the validator may see a mismatch with its locally stored observation and attempt unnecessary re-proposals
4. **Operational Confusion**: The mismatch breaks the assumption that certified updates match local proposals

While this does not cause:
- Funds loss or theft (Critical)
- Consensus safety violations (Critical)  
- Network halts or validator crashes (High)

It does create operational state inconsistencies that require understanding and potentially manual intervention to resolve, fitting the Medium severity category.

## Likelihood Explanation

**Moderate Likelihood**

This vulnerability can trigger during normal validator operations without any attacker intervention:

1. **Natural Triggering**: OIDC providers (Google, GitHub, etc.) periodically rotate their JWKs. The JWKObserver polls every 10 seconds [9](#0-8) , so consecutive fetches can return different content
2. **Timing Window**: The race condition occurs in the narrow window between broadcast completion and abort signal processing, which is possible due to concurrent tokio task execution
3. **No Byzantine Behavior Required**: This is a timing-based race condition in normal operations, not requiring any malicious actors
4. **Version Collision**: Both observations generate proposals with the same version (on_chain_version + 1), making them appear valid during the race window

The likelihood increases when:
- JWK providers perform rapid key rotations
- Network latency causes observation timing variations
- Multiple validators observe simultaneously, increasing concurrent broadcast load

## Recommendation

Add validation in `process_quorum_certified_update()` to ensure the received QC matches the current proposal:

```rust
pub fn process_quorum_certified_update(&mut self, update: QuorumCertifiedUpdate) -> Result<()> {
    let issuer = update.update.issuer.clone();
    let state = self.states_by_issuer.entry(issuer.clone()).or_default();
    match &state.consensus_state {
        ConsensusState::InProgress { my_proposal, .. } => {
            // Validate that the QC matches the current proposal
            if update.update != my_proposal.observed {
                return Err(anyhow!(
                    "QC content mismatch: received QC for different proposal than current InProgress state"
                ));
            }
            
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
        _ => Err(anyhow!(
            "qc update not expected for issuer {:?} in state {}",
            String::from_utf8(issuer.clone()),
            state.consensus_state.name()
        )),
    }
}
```

This ensures the certified update matches what the validator actually proposed, preventing state inconsistencies.

## Proof of Concept

The vulnerability can be demonstrated through the following sequence, which requires access to the validator's internal timing but represents a realistic operational scenario:

1. Configure a test OIDC provider that returns different JWK sets on consecutive fetches
2. Deploy JWKObserver with a short polling interval (e.g., 1 second for testing)
3. Ensure the reliable broadcast completes quickly (small validator set)
4. Observe the race condition when:
   - First observation creates proposal P1 and starts broadcast
   - Second observation creates proposal P2 before broadcast #1 is aborted
   - Broadcast #1 completes and pushes QC to channel
   - State processes QC for P1 while showing InProgress with P2
   - Resulting Finished state has mismatched my_proposal and quorum_certified

The race condition is timing-dependent but reproducible under the right network and observation conditions, particularly when OIDC providers update their JWKs rapidly.

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

**File:** crates/aptos-jwk-consensus/src/jwk_manager/mod.rs (L122-122)
```rust
                        Duration::from_secs(10),
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager/mod.rs (L196-199)
```rust
        if state.observed.as_ref() != state.on_chain.as_ref().map(ProviderJWKs::jwks) {
            let observed = ProviderJWKs {
                issuer: issuer.clone(),
                version: state.on_chain_version() + 1,
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

**File:** crates/aptos-jwk-consensus/src/jwk_manager/mod.rs (L332-343)
```rust
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
```

**File:** crates/channel/src/message_queues.rs (L142-146)
```rust
                QueueStyle::LIFO | QueueStyle::KLAST => {
                    let oldest = key_message_queue.pop_front();
                    key_message_queue.push_back(message);
                    oldest
                },
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

**File:** crates/aptos-jwk-consensus/src/update_certifier.rs (L67-74)
```rust
        let task = async move {
            let qc_update = rb.broadcast(req, agg_state).await.expect("cannot fail");
            ConsensusMode::log_certify_done(epoch, &qc_update);
            let session_key = ConsensusMode::session_key_from_qc(&qc_update);
            match session_key {
                Ok(key) => {
                    let _ = qc_update_tx.push(key, qc_update);
                },
```
