# Audit Report

## Title
Silent JWK Consensus Failure Allows Validator State Divergence

## Summary
When `update_certifier.start_produce()` fails in the JWK consensus per-key mode, the error is logged but not acted upon, allowing the consensus manager to continue without participating in consensus for that specific JWK update. This creates a persistent consensus participation gap that can lead to validator state divergence.

## Finding Description

The `KeyLevelConsensusManager` handles JWK (JSON Web Key) consensus for OpenID Connect providers. When a validator observes a JWK update from an OIDC provider, it initiates consensus through `maybe_start_consensus()`. [1](#0-0) 

The `start_produce()` call can fail if the data cannot be properly converted to the internal representation. This conversion fails when: [2](#0-1) 

The failure conditions include:
- JWK count != 1 (line 361-364)
- JWK conversion failure (line 365-366)  
- Version underflow when version=0 (line 367-370)

When `start_produce()` fails, the error propagates through `maybe_start_consensus()` and `process_new_observation()`. However, in the main event loop: [3](#0-2) 

The error is only logged and the loop continues. Critically, when `start_produce()` fails, the consensus state is never inserted into `states_by_key` (lines 216-228 are not reached), meaning:

1. This validator does NOT participate in consensus for this key
2. The update is silently dropped  
3. If other validators successfully process the update, state divergence occurs
4. The periodic observer will retry every 10 seconds, but if the issue persists (e.g., consistently malformed data from a compromised OIDC provider), the failure repeats indefinitely [4](#0-3) 

This breaks the **Consensus Safety** and **State Consistency** invariants, as validators should participate in consensus when they have valid observations, and all validators should maintain consistent state.

## Impact Explanation

**Medium Severity** - This qualifies as "State inconsistencies requiring intervention" per the Aptos bug bounty program.

The impact includes:
- **Consensus Participation Gap**: The affected validator silently fails to participate in JWK consensus for specific keys
- **State Divergence Risk**: Other validators may successfully certify the update, leading to inconsistent JWK state across the network
- **Security Update Failures**: Critical key rotations may be missed, potentially allowing transactions signed with revoked keys to be accepted by this validator
- **Silent Failure**: Operators may not be aware of the issue without actively monitoring error logs

This does not reach Critical or High severity because:
- It affects only one validator initially
- It does not directly lead to fund loss
- It does not cause total network failure
- However, it does create state inconsistencies requiring operator intervention

## Likelihood Explanation

**Moderate Likelihood** - This can occur in several realistic scenarios:

1. **Malicious OIDC Provider**: An attacker compromising an OIDC provider could serve malformed JWK data with version=0 or incorrect JWK counts
2. **OIDC Provider Bugs**: Legitimate bugs in OIDC provider implementations could produce malformed responses
3. **Network/Proxy Issues**: Data corruption during transit could malform the JWK response
4. **Protocol Violations**: OIDC providers not following the expected format

The likelihood is moderate rather than high because it requires the JWK data to be malformed in specific ways, but such malformations are realistic given external dependencies on OIDC providers.

## Recommendation

Implement explicit error handling that:
1. Tracks consecutive failures for each key
2. Raises alerts after N consecutive failures
3. Optionally isolates problematic keys to prevent log spam

```rust
fn maybe_start_consensus(&mut self, update: KeyLevelUpdate) -> Result<()> {
    // ... existing code ...
    
    let abort_handle = self
        .update_certifier
        .start_produce(
            self.epoch_state.clone(),
            update_translated,
            self.qc_update_tx.clone(),
        )
        .context("maybe_start_consensus failed at update_certifier.start_produce")?;

    // Track successful start
    self.mark_consensus_start_success(&update.issuer, &update.kid);
    
    // ... rest of function ...
}

// In the main run loop:
if let Err(e) = handle_result {
    error!(
        epoch = this.epoch_state.epoch,
        "KeyLevelJWKManager error from handling: {e:#}"
    );
    
    // Track persistent failures and alert
    this.track_and_alert_persistent_failures(&e);
}
```

Additionally, add metrics/counters for consensus start failures to enable monitoring and alerting.

## Proof of Concept

```rust
#[cfg(test)]
mod test_consensus_failure {
    use super::*;
    
    #[test]
    fn test_malformed_jwk_causes_silent_consensus_failure() {
        // Create KeyLevelConsensusManager with mock update_certifier
        let mut manager = create_test_manager();
        
        // Simulate malformed JWK data with version=0
        let malformed_update = KeyLevelUpdate {
            issuer: b"test-issuer".to_vec(),
            base_version: 0, // This will cause version underflow
            kid: b"test-kid".to_vec(),
            to_upsert: Some(test_jwk()),
        };
        
        // Call maybe_start_consensus
        let result = manager.maybe_start_consensus(malformed_update);
        
        // Verify error is returned
        assert!(result.is_err());
        
        // Verify state was NOT inserted (consensus not started)
        let key = (b"test-issuer".to_vec(), b"test-kid".to_vec());
        assert!(manager.states_by_key.get(&key).is_none());
        
        // In the actual run loop, this error would be logged but ignored,
        // and the system would continue processing other updates
    }
}
```

## Notes

This vulnerability is present in both `KeyLevelConsensusManager` and `IssuerLevelConsensusManager`, suggesting it may be a systemic design issue rather than an isolated bug. The identical error handling pattern across both implementations indicates this behavior may have been intentional for fault tolerance, but it creates security gaps when dealing with persistent failures from external systems.

### Citations

**File:** crates/aptos-jwk-consensus/src/jwk_manager_per_key.rs (L207-214)
```rust
        let abort_handle = self
            .update_certifier
            .start_produce(
                self.epoch_state.clone(),
                update_translated,
                self.qc_update_tx.clone(),
            )
            .context("maybe_start_consensus failed at update_certifier.start_produce")?;
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager_per_key.rs (L435-440)
```rust
            if let Err(e) = handle_result {
                error!(
                    epoch = this.epoch_state.epoch,
                    "KeyLevelJWKManager error from handling: {e:#}"
                );
            }
```

**File:** types/src/jwks/mod.rs (L360-370)
```rust
    pub fn try_from_issuer_level_repr(repr: &ProviderJWKs) -> anyhow::Result<Self> {
        ensure!(
            repr.jwks.len() == 1,
            "wrapped repr of a key-level update should have exactly 1 jwk"
        );
        let jwk =
            JWK::try_from(&repr.jwks[0]).context("try_from_issuer_level_repr failed on JWK")?;
        let base_version = repr
            .version
            .checked_sub(1)
            .context("try_from_issuer_level_repr on version")?;
```

**File:** crates/aptos-jwk-consensus/src/jwk_observer.rs (L72-83)
```rust
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
```
