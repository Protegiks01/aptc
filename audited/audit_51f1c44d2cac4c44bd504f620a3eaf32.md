# Audit Report

## Title
Unbounded HashMap Growth via Malicious JWK Consensus RPC Requests Enables Validator Node Memory Exhaustion DoS

## Summary
The `process_peer_request()` function in the JWK consensus manager creates HashMap entries for arbitrary `(issuer, kid)` pairs without validation or bounds checking. Malicious validators can spam requests with random pairs, causing unbounded memory growth that persists indefinitely due to a flawed cleanup logic, eventually crashing victim nodes through memory exhaustion.

## Finding Description

The vulnerability exists in the per-key JWK consensus implementation where validator peers exchange observation requests. The critical flaw is at: [1](#0-0) 

When a validator receives a `KeyLevelObservationRequest`, the code unconditionally creates a new `ConsensusState::NotStarted` entry in the `states_by_key` HashMap for any `(issuer, kid)` pair that doesn't exist. There is no validation that:
- The issuer is a legitimate OIDC provider
- The kid is a valid key ID
- The total number of entries is bounded

The HashMap structure is defined as: [2](#0-1) 

Where `Issuer` and `KID` are both `Vec<u8>`, allowing arbitrary byte sequences: [3](#0-2) 

**The Critical Flaw in Cleanup Logic:**

The `reset_with_on_chain_state()` function attempts to clean up stale entries: [4](#0-3) 

However, this logic has a fatal flaw: For arbitrary `(issuer, kid)` pairs that never existed on-chain:
- `new_onchain_jwks.get(issuer)` returns `None` → `unwrap_or_default()` returns `0`
- `self.onchain_jwks.get(issuer)` returns `None` → `unwrap_or_default()` returns `0`  
- The condition `0 == 0` evaluates to `true`, so the entry is **retained**

This means malicious entries are never cleaned up—they persist forever in memory.

**Attack Path:**

1. Malicious validator node connects to the validator network (requires being part of the active validator set)
2. Repeatedly sends `KeyLevelObservationRequest` messages with randomly generated `(issuer, kid)` pairs
3. Each unique pair creates a new HashMap entry on victim validators
4. The network layer forwards these requests without validation: [5](#0-4) 

5. Entries accumulate indefinitely, consuming memory
6. Eventually triggers OOM (Out of Memory) conditions, crashing victim validators

This breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits."

## Impact Explanation

This qualifies as **High Severity** per Aptos bug bounty criteria:

- **Validator node slowdowns**: As memory fills, garbage collection pressure increases, degrading node performance
- **API crashes**: OOM can crash the validator process entirely
- **Significant protocol violations**: Violates resource limit invariants

Could escalate to **Critical Severity** if:
- Multiple validators are simultaneously crashed
- Causes "Total loss of liveness/network availability" if enough validators become unavailable

The attack requires minimal resources from the attacker (just network bandwidth to send RPC messages) but can force victim nodes to consume gigabytes of memory.

## Likelihood Explanation

**High Likelihood:**

- **Low barrier to entry**: Any active validator in the epoch can exploit this (doesn't require stake majority or collusion)
- **Easy to execute**: Simple automated script to generate and send random `(issuer, kid)` pairs
- **No detection**: The malicious requests appear identical to legitimate consensus messages
- **No rate limiting**: No bounds checking or rate limiting on HashMap growth
- **Persistent impact**: Entries never get cleaned up, so even brief attack periods cause permanent memory leaks

The attack is particularly dangerous because:
- It's stealthy (looks like normal consensus traffic)
- Doesn't require continuous attack (damage persists after attack stops)
- Affects all validators that process the malicious messages

## Recommendation

Implement multiple defense layers:

**1. Validate issuer against on-chain supported providers:**

```rust
pub fn process_peer_request(&mut self, rpc_req: IncomingRpcRequest) -> Result<()> {
    let IncomingRpcRequest {
        msg,
        mut response_sender,
        ..
    } = rpc_req;
    match msg {
        JWKConsensusMsg::KeyLevelObservationRequest(request) => {
            let ObservedKeyLevelUpdateRequest { issuer, kid, .. } = request;
            
            // DEFENSE 1: Validate issuer exists on-chain
            if !self.onchain_jwks.contains_key(&issuer) {
                debug!(
                    issuer = String::from_utf8(issuer.clone()).ok(),
                    "Rejecting request for unknown issuer"
                );
                return Ok(()); // Silently ignore invalid issuer
            }
            
            let consensus_state = self
                .states_by_key
                .entry((issuer.clone(), kid.clone()))
                .or_default();
            // ... rest of function
        },
        _ => {
            bail!("unexpected rpc: {}", msg.name());
        },
    }
}
```

**2. Add bounded map with size limits:**

```rust
// In struct definition
const MAX_CONSENSUS_STATES: usize = 10000; // Reasonable bound

// Before inserting
if self.states_by_key.len() >= MAX_CONSENSUS_STATES {
    warn!("states_by_key at capacity, rejecting new entry");
    return Ok(());
}
```

**3. Fix cleanup logic to remove entries for unknown issuers:**

```rust
self.states_by_key.retain(|(issuer, _), _| {
    // Only keep entries for issuers that exist on-chain
    new_onchain_jwks.contains_key(issuer)
        && new_onchain_jwks.get(issuer).map(|jwks| jwks.version).unwrap_or_default()
            == self.onchain_jwks.get(issuer).map(|jwks| jwks.version).unwrap_or_default()
});
```

**4. Add periodic cleanup of NotStarted states:**

```rust
// Clean up stale NotStarted entries periodically
self.states_by_key.retain(|_, state| {
    !matches!(state, ConsensusState::NotStarted)
});
```

## Proof of Concept

```rust
#[cfg(test)]
mod memory_exhaustion_poc {
    use super::*;
    use aptos_crypto::bls12381;
    use aptos_types::validator_verifier::ValidatorVerifier;
    
    #[test]
    fn test_unbounded_hashmap_growth() {
        // Setup test environment
        let (private_key, public_key) = bls12381::PrivateKey::generate_for_testing();
        let my_addr = AccountAddress::random();
        let epoch_state = Arc::new(EpochState::new(
            1,
            ValidatorVerifier::new(vec![(my_addr, public_key)]),
        ));
        
        let (network_sender, _network_events) = aptos_channels::new_test(10);
        let rb = ReliableBroadcast::new(
            vec![my_addr],
            network_sender,
            ExponentialBackoff::from_millis(10),
            aptos_time_service::TimeService::mock(),
            Duration::from_secs(30),
            1.0,
            1000,
        );
        
        let vtxn_pool = VTxnPoolState::default();
        let mut manager = KeyLevelConsensusManager::new(
            Arc::new(private_key),
            my_addr,
            epoch_state,
            rb,
            vtxn_pool,
        );
        
        // Simulate attacker sending 100,000 malicious requests
        let initial_memory = manager.states_by_key.len();
        
        for i in 0..100_000 {
            let malicious_issuer = format!("fake_issuer_{}", i).into_bytes();
            let malicious_kid = format!("fake_kid_{}", i).into_bytes();
            
            let request = ObservedKeyLevelUpdateRequest {
                epoch: 1,
                issuer: malicious_issuer,
                kid: malicious_kid,
            };
            
            let rpc_req = IncomingRpcRequest {
                msg: JWKConsensusMsg::KeyLevelObservationRequest(request),
                sender: AccountAddress::random(),
                response_sender: Box::new(DummyRpcResponseSender::new(
                    Arc::new(RwLock::new(vec![]))
                )),
            };
            
            manager.process_peer_request(rpc_req).unwrap();
        }
        
        // Verify unbounded growth
        let final_memory = manager.states_by_key.len();
        assert_eq!(final_memory - initial_memory, 100_000);
        println!("Memory grew by {} entries (unbounded!)", final_memory - initial_memory);
        
        // Verify cleanup doesn't remove malicious entries
        manager.reset_with_on_chain_state(AllProvidersJWKs::default()).unwrap();
        let after_cleanup = manager.states_by_key.len();
        
        // BUG: Cleanup fails to remove entries for unknown issuers
        assert_eq!(after_cleanup, final_memory, 
            "Cleanup should have removed malicious entries but didn't!");
    }
}
```

## Notes

The vulnerability is particularly severe because:
- It combines unbounded growth with permanent persistence (no cleanup)
- Can be exploited passively (malicious messages forwarded by honest nodes)
- Affects the critical JWK consensus path used for keyless account authentication
- Memory exhaustion can cascade to affect other subsystems on the validator node

### Citations

**File:** aptos-core-074/crates/aptos-jwk-consensus/src/jwk_manager_per_key.rs (L59-59)
```rust

```

**File:** aptos-core-074/crates/aptos-jwk-consensus/src/jwk_manager_per_key.rs (L244-254)
```rust

```

**File:** aptos-core-074/crates/aptos-jwk-consensus/src/jwk_manager_per_key.rs (L274-277)
```rust

```

**File:** aptos-core-074/types/src/jwks/mod.rs (L36-38)
```rust

```

**File:** aptos-core-074/crates/aptos-jwk-consensus/src/network.rs (L191-203)
```rust

```
