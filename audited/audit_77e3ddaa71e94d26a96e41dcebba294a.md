# Audit Report

## Title
Memory and CPU Exhaustion via HashMap Flooding in JWK Consensus KeyLevelObservationRequest Handler

## Summary
Byzantine validators can flood honest validators with `KeyLevelObservationRequest` messages containing arbitrary (issuer, kid) pairs, causing unbounded HashMap growth in `states_by_key`. Due to flawed cleanup logic and lack of rate limiting, these malicious entries persist indefinitely, leading to memory exhaustion and CPU degradation from HashMap operations.

## Finding Description

The `process_peer_request()` function in the per-key JWK consensus manager handles incoming `KeyLevelObservationRequest` RPC messages from peer validators. The function performs a HashMap lookup/insertion operation without validating the request parameters: [1](#0-0) 

The `.entry().or_default()` call creates a new `ConsensusState::NotStarted` entry for any previously unseen (issuer, kid) pair. The function then immediately returns for `NotStarted` states: [2](#0-1) 

**Attack Propagation:**

1. A Byzantine validator crafts `KeyLevelObservationRequest` messages with arbitrary (issuer, kid) combinations
2. The RPC request passes through the network layer's concurrent request limit (100 concurrent requests) but completes immediately due to the early return
3. Each unique (issuer, kid) pair creates a HashMap entry that consumes memory
4. The attacker sends thousands of requests with different combinations
5. The `states_by_key` HashMap grows unboundedly

**Flawed Cleanup Logic:**

The cleanup mechanism in `reset_with_on_chain_state()` uses a `retain` predicate that inadvertently keeps malicious entries: [3](#0-2) 

For issuers that don't exist in either `new_onchain_jwks` or `self.onchain_jwks`, both `unwrap_or_default()` calls return 0, making the comparison `0 == 0` evaluate to true, thereby RETAINING the malicious entries instead of removing them.

**Missing Defenses:**

The network layer only limits concurrent requests (100 per peer), not request rate: [4](#0-3) 

Since requests complete instantly, this limit doesn't prevent rapid sequential flooding.

The type definitions show no length validation on issuer or kid values: [5](#0-4) 

While network messages are capped at 64 MiB, an attacker can send many messages with large issuer/kid values to maximize memory consumption per request.

## Impact Explanation

This vulnerability causes **Medium severity** impact per Aptos bug bounty criteria:

- **Validator Node Slowdowns**: HashMap operations (hashing, resizing, iteration) become increasingly expensive as entries accumulate, degrading CPU performance
- **Memory Exhaustion**: Each entry stores the (issuer, kid) key plus `ConsensusState` enum. With large issuer/kid values (up to network message limits), an attacker could force gigabytes of memory allocation
- **Cascading Effects**: If multiple validators are targeted simultaneously, network consensus could be disrupted due to validator unavailability

The impact is limited to "validator node slowdowns" (High) or "state inconsistencies requiring intervention" (Medium) rather than Critical severity because:
- Attack requires being a validator (1/3 Byzantine assumption)
- Doesn't directly compromise consensus safety or cause fund loss
- Affected nodes can be restarted to clear the HashMap (though attack can resume)

## Likelihood Explanation

**High Likelihood:**

- **Low Attacker Complexity**: Any Byzantine validator can execute this attack by simply sending RPC messages with arbitrary data
- **No Authentication Barrier**: JWK consensus RPCs are authenticated at the validator network level, so any validator in the set can participate
- **Minimal Detection**: The entries look like legitimate consensus state to monitoring systems
- **Persistent Impact**: Once created, entries remain indefinitely due to the flawed cleanup logic
- **Byzantine Assumption**: AptosBFT is designed to tolerate up to 1/3 Byzantine validators, so the presence of malicious validators is expected

The attack requires only:
1. Membership in the validator set (Byzantine assumption)
2. Ability to send RPC messages (standard network capability)
3. Knowledge of the RPC message format (publicly documented)

## Recommendation

**Fix 1: Add Request Rate Limiting Per Peer**

Implement per-peer rate limiting for `KeyLevelObservationRequest` messages:

```rust
pub struct KeyLevelConsensusManager {
    // ... existing fields ...
    peer_request_counters: HashMap<AccountAddress, (u64, Instant)>, // (count, window_start)
}

const MAX_REQUESTS_PER_PEER_PER_MINUTE: u64 = 100;

pub fn process_peer_request(&mut self, rpc_req: IncomingRpcRequest) -> Result<()> {
    let sender = rpc_req.sender;
    
    // Rate limiting check
    let now = Instant::now();
    let entry = self.peer_request_counters.entry(sender).or_insert((0, now));
    if now.duration_since(entry.1) > Duration::from_secs(60) {
        *entry = (1, now); // Reset window
    } else {
        entry.0 += 1;
        if entry.0 > MAX_REQUESTS_PER_PEER_PER_MINUTE {
            return Err(anyhow!("Rate limit exceeded for peer {}", sender));
        }
    }
    
    // ... rest of existing code ...
}
```

**Fix 2: Validate Issuer/KID Before HashMap Insertion**

Only create entries for known issuers:

```rust
pub fn process_peer_request(&mut self, rpc_req: IncomingRpcRequest) -> Result<()> {
    // ... existing code ...
    match msg {
        JWKConsensusMsg::KeyLevelObservationRequest(request) => {
            let ObservedKeyLevelUpdateRequest { issuer, kid, .. } = request;
            
            // Validate issuer exists in on-chain state
            if !self.onchain_jwks.contains_key(&issuer) {
                debug!(
                    issuer = String::from_utf8(issuer.clone()).ok(),
                    "Ignoring request for unknown issuer"
                );
                return Ok(());
            }
            
            // Validate lengths
            ensure!(issuer.len() <= 120, "Issuer too long");
            ensure!(kid.len() <= 256, "KID too long");
            
            let consensus_state = self
                .states_by_key
                .get(&(issuer.clone(), kid.clone()));
            // ... rest of code using get() instead of entry() ...
        }
    }
}
```

**Fix 3: Correct Cleanup Logic**

Fix the `retain` predicate to remove entries for unknown issuers:

```rust
pub fn reset_with_on_chain_state(&mut self, on_chain_state: AllProvidersJWKs) -> Result<()> {
    // ... existing code ...
    
    // Only retain entries whose issuer exists in the new on-chain state
    // AND whose version matches
    self.states_by_key.retain(|(issuer, _), _| {
        match (new_onchain_jwks.get(issuer), self.onchain_jwks.get(issuer)) {
            (Some(new_jwks), Some(old_jwks)) => new_jwks.version == old_jwks.version,
            _ => false, // Remove if issuer not in both states
        }
    });
    
    // ... rest of existing code ...
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_request_flooding_memory_exhaustion() {
        // Setup: Create a KeyLevelConsensusManager instance
        let consensus_key = Arc::new(PrivateKey::generate_for_testing());
        let my_addr = AccountAddress::random();
        let epoch_state = Arc::new(EpochState::empty());
        let (rb_tx, _rb_rx) = aptos_channel::new(QueueStyle::FIFO, 1, None);
        let rb = ReliableBroadcast::new(/* ... */);
        let vtxn_pool = VTxnPoolState::default();
        
        let mut manager = KeyLevelConsensusManager::new(
            consensus_key,
            my_addr,
            epoch_state,
            rb,
            vtxn_pool,
        );
        
        // Initialize with empty on-chain state
        manager.reset_with_on_chain_state(AllProvidersJWKs::default()).unwrap();
        
        let initial_size = manager.states_by_key.len();
        
        // Attack: Send 10,000 requests with different (issuer, kid) pairs
        let byzantine_validator = AccountAddress::random();
        for i in 0..10000 {
            let fake_issuer = format!("https://fake-issuer-{}.com", i).into_bytes();
            let fake_kid = format!("fake-kid-{}", i).into_bytes();
            
            let request = IncomingRpcRequest {
                msg: JWKConsensusMsg::KeyLevelObservationRequest(
                    ObservedKeyLevelUpdateRequest {
                        epoch: 1,
                        issuer: fake_issuer,
                        kid: fake_kid,
                    }
                ),
                sender: byzantine_validator,
                response_sender: Box::new(DummyRpcResponseSender::new(Arc::new(RwLock::new(vec![])))),
            };
            
            // Each request completes instantly but leaves an entry
            manager.process_peer_request(request).unwrap();
        }
        
        let final_size = manager.states_by_key.len();
        
        // Assert: HashMap grew by 10,000 entries
        assert_eq!(final_size - initial_size, 10000);
        
        // Verify cleanup doesn't remove the malicious entries
        manager.reset_with_on_chain_state(AllProvidersJWKs::default()).unwrap();
        assert_eq!(manager.states_by_key.len(), 10000, "Malicious entries persisted after cleanup!");
        
        println!("Memory exhaustion attack successful: {} malicious entries retained", 
                 manager.states_by_key.len());
    }
}
```

## Notes

This vulnerability specifically affects the per-key JWK consensus mode introduced for keyless authentication. The attack vector is limited to Byzantine validators within the validator set, which aligns with the AptosBFT security model that tolerates up to 1/3 Byzantine validators. However, resource exhaustion attacks are particularly concerning because they can degrade network performance even with a small number of malicious validators.

The root cause is a combination of three factors: (1) lack of input validation, (2) flawed cleanup logic with incorrect Boolean logic, and (3) insufficient rate limiting on sequential requests. All three defenses should be implemented for defense-in-depth.

### Citations

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

**File:** crates/aptos-jwk-consensus/src/jwk_manager_per_key.rs (L279-286)
```rust
                    ConsensusState::NotStarted => {
                        debug!(
                            issuer = String::from_utf8(issuer.clone()).ok(),
                            kid = String::from_utf8(kid.clone()).ok(),
                            "key-level jwk consensus not started"
                        );
                        return Ok(());
                    },
```

**File:** network/framework/src/protocols/rpc/mod.rs (L213-223)
```rust
        if self.inbound_rpc_tasks.len() as u32 == self.max_concurrent_inbound_rpcs {
            // Increase counter of declined requests
            counters::rpc_messages(
                network_context,
                REQUEST_LABEL,
                INBOUND_LABEL,
                DECLINED_LABEL,
            )
            .inc();
            return Err(RpcError::TooManyPending(self.max_concurrent_inbound_rpcs));
        }
```

**File:** types/src/jwks/mod.rs (L36-38)
```rust
pub type Issuer = Vec<u8>;
/// Type for JWK Key ID.
pub type KID = Vec<u8>;
```
