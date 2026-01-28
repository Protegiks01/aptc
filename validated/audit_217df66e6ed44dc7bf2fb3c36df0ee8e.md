# Audit Report

## Title
Unbounded Memory Exhaustion via Byzantine Validator JWK Consensus Request Flooding in Per-Key Mode

## Summary
Byzantine validators can exhaust validator node memory by flooding the JWK consensus system with arbitrary (issuer, kid) pairs through `KeyLevelObservationRequest` messages. The vulnerability stems from unconditional HashMap entry creation without validation, combined with broken cleanup logic that indefinitely retains malicious entries.

## Finding Description

The JWK consensus system in per-key mode maintains a `states_by_key` HashMap to track consensus state for each (issuer, kid) pair. [1](#0-0) 

When a `KeyLevelObservationRequest` arrives, `process_peer_request()` unconditionally creates a HashMap entry using `entry().or_default()` without validating that the issuer exists in the on-chain `SupportedOIDCProviders` list. [2](#0-1) 

Both `Issuer` and `KID` are type aliases for `Vec<u8>` with no inherent length restrictions. [3](#0-2) 

Although the function returns early for `NotStarted` states without sending a response, the HashMap entry persists in memory. [4](#0-3) 

The cleanup logic in `reset_with_on_chain_state()` contains a critical bug. For issuers not present in the on-chain state, both sides of the equality comparison use `unwrap_or_default()` which returns 0, causing the retention condition `0 == 0` to evaluate to `true`, thereby keeping malicious entries indefinitely. [5](#0-4) 

While epoch validation occurs at the `EpochManager` level, it only filters messages with mismatched epoch numbers and does not validate the content of requests within the current epoch. [6](#0-5) 

The network layer enforces a limit of 100 concurrent inbound RPCs per peer, but this does not prevent sequential batches of requests from accumulating unbounded HashMap entries over time. [7](#0-6) 

**Attack Execution Path:**
1. Byzantine validator (≤1/3 of validator set) crafts `KeyLevelObservationRequest` messages with arbitrary (issuer, kid) pairs
2. Requests pass epoch validation if sent with correct epoch number
3. `process_peer_request()` creates HashMap entries with `ConsensusState::NotStarted`
4. Function returns early, leaving entries in memory
5. Attacker repeats with unique pairs in sequential batches of 100
6. Cleanup logic fails to remove entries for non-existent issuers due to `0 == 0` comparison
7. HashMap grows unboundedly until memory exhaustion occurs

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program's impact categories:

- **Validator Node Slowdowns (High)**: Memory exhaustion causes performance degradation affecting consensus participation and block processing speed. This aligns directly with the bounty program's High severity category for "DoS through resource exhaustion."
- **Resource Exhaustion**: Violates the requirement that protocol operations respect resource limits, as arbitrary external input can consume unbounded memory through a protocol-level bug.
- **Potential Node Crashes**: In severe cases with sustained attacks or multiple attacking validators, memory pressure could crash validator nodes, impacting network stability.

This is a protocol-level resource exhaustion vulnerability, distinct from network-layer DoS attacks. The vulnerability exploits two specific bugs: missing validation against `SupportedOIDCProviders` and broken cleanup logic with `unwrap_or_default()`.

## Likelihood Explanation

**High Likelihood:**

The attack requires only a Byzantine validator (≤1/3 of validator set) sending well-formed RPC messages with random byte sequences, which is:
- **Trivially executable**: No special timing, state conditions, or complex coordination required
- **Within standard threat model**: Byzantine validators (≤1/3) are part of the BFT adversary model
- **Unmitigated**: No validation checks issuer against `SupportedOIDCProviders`, no per-key memory limits exist, no rate limiting beyond the 100 concurrent RPC limit
- **Persistent**: Cleanup logic bug ensures malicious entries survive indefinitely across epoch transitions and on-chain state updates

The network layer's 100 concurrent RPC limit per peer provides minimal protection as attackers can send unlimited sequential batches over time, accumulating entries indefinitely.

## Recommendation

Implement the following mitigations:

1. **Validate issuers before creating entries**: Check that the issuer exists in `SupportedOIDCProviders` before inserting into `states_by_key`.

2. **Fix cleanup logic**: Modify `reset_with_on_chain_state()` to explicitly remove entries for issuers not in the new on-chain state:
```rust
self.states_by_key.retain(|(issuer, _), _| {
    let new_version = new_onchain_jwks.get(issuer).map(|jwks| jwks.version);
    let old_version = self.onchain_jwks.get(issuer).map(|jwks| jwks.version);
    
    match (new_version, old_version) {
        (Some(new), Some(old)) => new == old,
        _ => false, // Remove entries for non-existent issuers
    }
});
```

3. **Add memory limits**: Implement a bounded size for `states_by_key` with an eviction policy for the oldest entries.

4. **Add rate limiting**: Implement per-peer rate limiting for `KeyLevelObservationRequest` messages beyond the concurrent limit.

## Proof of Concept

A Byzantine validator sends sequential batches of RPC requests:

```rust
// Simplified PoC showing the attack pattern
for batch in 0..1000 {
    let requests: Vec<_> = (0..100).map(|i| {
        KeyLevelObservationRequest {
            epoch: current_epoch,
            issuer: format!("malicious_issuer_{}_{}",batch, i).into_bytes(),
            kid: format!("malicious_kid_{}_{}",batch, i).into_bytes(),
        }
    }).collect();
    
    // Send batch, wait for processing, repeat
    send_rpc_batch(requests).await;
}

// Result: 100,000 HashMap entries consuming ~30MB memory,
// persisting indefinitely due to cleanup bug
```

The malicious entries accumulate in `states_by_key` and are never removed because the cleanup logic retains all entries where both issuer versions evaluate to 0 (non-existent issuer case).

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

**File:** crates/aptos-jwk-consensus/src/jwk_manager_per_key.rs (L274-277)
```rust
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

**File:** types/src/jwks/mod.rs (L36-38)
```rust
pub type Issuer = Vec<u8>;
/// Type for JWK Key ID.
pub type KID = Vec<u8>;
```

**File:** crates/aptos-jwk-consensus/src/epoch_manager.rs (L99-99)
```rust
        if Some(rpc_request.msg.epoch()) == self.epoch_state.as_ref().map(|s| s.epoch) {
```

**File:** network/framework/src/constants.rs (L15-15)
```rust
pub const MAX_CONCURRENT_INBOUND_RPCS: u32 = 100;
```
