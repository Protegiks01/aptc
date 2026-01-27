# Audit Report

## Title
Unbounded Memory Exhaustion via Byzantine Validator JWK Consensus Request Flooding in Per-Key Mode

## Summary
Byzantine validators can exhaust validator node memory by flooding the system with arbitrary (issuer, kid) pairs through `KeyLevelObservationRequest` messages. The `process_peer_request()` function creates persistent HashMap entries for each unique pair without validation or resource limits, and the cleanup logic fails to remove these malicious entries, enabling unbounded memory growth.

## Finding Description

The JWK consensus system in per-key mode maintains a `states_by_key: HashMap<(Issuer, KID), ConsensusState<ObservedKeyLevelUpdate>>` to track consensus state for each key. [1](#0-0) 

When a `KeyLevelObservationRequest` arrives via `process_peer_request()`, the code unconditionally creates a HashMap entry for the requested (issuer, kid) pair using `entry().or_default()`: [2](#0-1) 

The `Issuer` and `KID` types are both `Vec<u8>` with no inherent length restrictions: [3](#0-2) 

Although the function returns early for `NotStarted` states without sending a response, the HashMap entry persists: [4](#0-3) 

The cleanup logic in `reset_with_on_chain_state()` uses a retain operation that evaluates to `true` for non-existent issuers (both versions are 0), causing arbitrary entries to persist indefinitely: [5](#0-4) 

**Attack Path:**
1. Byzantine validator sends `KeyLevelObservationRequest` with arbitrary (issuer, kid) = (b"malicious_issuer_1", b"kid_1")
2. `process_peer_request()` creates HashMap entry with `ConsensusState::NotStarted`
3. Function returns early, but entry persists
4. Attacker repeats with unique pairs: (b"malicious_issuer_2", b"kid_2"), (b"malicious_issuer_3", b"kid_3"), etc.
5. Network-layer rate limiting only prevents 100 concurrent requests, but sequential batches bypass this
6. HashMap grows unboundedly: 1M entries × (Issuer + KID + enum tag + HashMap overhead) ≈ several hundred MB to GB
7. Validator node experiences memory pressure, slowdowns, or crashes

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program:
- **Validator node slowdowns**: Memory exhaustion degrades node performance, affecting consensus participation
- **Potential DoS**: Severe cases could crash validator nodes, impacting network liveness
- **Resource Exhaustion**: Violates Invariant 9 requiring all operations to respect resource limits

If multiple validators are targeted simultaneously, this could degrade network performance or cause a liveness failure requiring intervention.

## Likelihood Explanation

**High Likelihood:**
- Byzantine validators (up to 1/3 of validator set) are part of the standard BFT adversary model
- Attack is trivial to execute: simply send RPC messages with random byte sequences
- No authentication beyond being in the validator set
- No per-session resource limits exist
- Network layer only limits concurrent requests (100), not total unique sessions
- Cleanup logic incorrectly retains malicious entries indefinitely

The network-layer limit of 100 concurrent inbound RPCs provides minimal protection since attackers can send sequential batches of 100 requests indefinitely.

## Recommendation

Implement bounded resource limits and validation for JWK consensus sessions:

```rust
// In KeyLevelConsensusManager
const MAX_CONSENSUS_SESSIONS: usize = 1000; // Limit total sessions

pub fn process_peer_request(&mut self, rpc_req: IncomingRpcRequest) -> Result<()> {
    let IncomingRpcRequest { msg, mut response_sender, .. } = rpc_req;
    match msg {
        JWKConsensusMsg::KeyLevelObservationRequest(request) => {
            let ObservedKeyLevelUpdateRequest { issuer, kid, .. } = request;
            
            // Validate issuer exists in onchain_jwks or supported providers
            if !self.onchain_jwks.contains_key(&issuer) {
                debug!("Rejecting request for unknown issuer");
                return Ok(());
            }
            
            // Check session limit before creating entry
            if !self.states_by_key.contains_key(&(issuer.clone(), kid.clone())) 
                && self.states_by_key.len() >= MAX_CONSENSUS_SESSIONS {
                warn!("Max consensus sessions reached, rejecting request");
                return Ok(());
            }
            
            let consensus_state = self.states_by_key
                .entry((issuer.clone(), kid.clone()))
                .or_default();
            // ... rest of logic
        }
        // ...
    }
}
```

Additionally, modify `reset_with_on_chain_state()` to actively remove entries for unknown issuers:

```rust
self.states_by_key.retain(|(issuer, _), _| {
    let issuer_exists = new_onchain_jwks.contains_key(issuer);
    let version_matches = new_onchain_jwks
        .get(issuer)
        .map(|jwks| jwks.version)
        .unwrap_or_default()
        == self.onchain_jwks
            .get(issuer)
            .map(|jwks| jwks.version)
            .unwrap_or_default();
    
    issuer_exists && version_matches // Only keep if issuer exists AND version matches
});
```

## Proof of Concept

```rust
// Proof of Concept demonstrating the vulnerability
// This would be added as a test in jwk_manager_per_key.rs

#[tokio::test]
async fn test_byzantine_flooding_attack() {
    use crate::types::{JWKConsensusMsg, ObservedKeyLevelUpdateRequest};
    use crate::network::IncomingRpcRequest;
    use aptos_types::jwks::{Issuer, KID};
    
    // Setup KeyLevelConsensusManager with test configuration
    let mut manager = create_test_manager(); // Helper function to create manager
    
    // Initial state: empty states_by_key
    assert_eq!(manager.states_by_key.len(), 0);
    
    // Simulate Byzantine validator sending 10,000 requests with unique (issuer, kid) pairs
    for i in 0..10000 {
        let malicious_issuer: Issuer = format!("attacker_issuer_{}", i).into_bytes();
        let malicious_kid: KID = format!("attacker_kid_{}", i).into_bytes();
        
        let request = ObservedKeyLevelUpdateRequest {
            epoch: 1,
            issuer: malicious_issuer.clone(),
            kid: malicious_kid.clone(),
        };
        
        let (response_tx, _response_rx) = oneshot::channel();
        let rpc_req = IncomingRpcRequest {
            msg: JWKConsensusMsg::KeyLevelObservationRequest(request),
            response_sender: response_tx,
            peer: create_test_peer_id(),
        };
        
        // Process request - this creates a HashMap entry
        manager.process_peer_request(rpc_req).unwrap();
    }
    
    // Verify: 10,000 entries were created
    assert_eq!(manager.states_by_key.len(), 10000);
    
    // Simulate on-chain state update (cleanup attempt)
    let on_chain_state = AllProvidersJWKs::default(); // Empty on-chain state
    manager.reset_with_on_chain_state(on_chain_state).unwrap();
    
    // BUG: Entries are NOT cleaned up because retain logic keeps them
    // Expected: 0, Actual: 10000
    assert_eq!(manager.states_by_key.len(), 10000, 
        "Malicious entries should be cleaned but persist indefinitely");
    
    println!("Attack successful: {} bogus entries consuming memory", 
        manager.states_by_key.len());
}
```

**Notes:**
- This vulnerability exists because `process_peer_request()` creates HashMap entries without validating that the (issuer, kid) pair corresponds to a legitimate consensus session
- The cleanup logic's comparison `0 == 0` evaluates to `true` for non-existent issuers, causing retention
- Byzantine validators in the AptosBFT model (up to 1/3 of validator set) can exploit this without additional privileges
- The attack bypasses network-layer rate limits by sending sequential batches rather than concurrent floods
- Memory consumption scales linearly with the number of unique (issuer, kid) pairs

### Citations

**File:** crates/aptos-jwk-consensus/src/jwk_manager_per_key.rs (L59-59)
```rust
    states_by_key: HashMap<(Issuer, KID), ConsensusState<ObservedKeyLevelUpdate>>,
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager_per_key.rs (L244-254)
```rust
        self.states_by_key.retain(|(issuer, _), _| {
            new_onchain_jwks
                .get(issuer)
                .map(|jwks| jwks.version)
                .unwrap_or_default()
                == self
                    .onchain_jwks
                    .get(issuer)
                    .map(|jwks| jwks.version)
                    .unwrap_or_default()
        });
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager_per_key.rs (L272-277)
```rust
            JWKConsensusMsg::KeyLevelObservationRequest(request) => {
                let ObservedKeyLevelUpdateRequest { issuer, kid, .. } = request;
                let consensus_state = self
                    .states_by_key
                    .entry((issuer.clone(), kid.clone()))
                    .or_default();
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager_per_key.rs (L279-285)
```rust
                    ConsensusState::NotStarted => {
                        debug!(
                            issuer = String::from_utf8(issuer.clone()).ok(),
                            kid = String::from_utf8(kid.clone()).ok(),
                            "key-level jwk consensus not started"
                        );
                        return Ok(());
```

**File:** types/src/jwks/mod.rs (L36-38)
```rust
pub type Issuer = Vec<u8>;
/// Type for JWK Key ID.
pub type KID = Vec<u8>;
```
