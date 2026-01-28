# Audit Report

## Title
Unbounded Memory Exhaustion via Malicious JWK Consensus Requests in Per-Key Mode

## Summary
Byzantine validators can exhaust memory on honest validators by flooding them with `KeyLevelObservationRequest` messages containing arbitrary (issuer, kid) pairs. The `process_peer_request()` function creates unbounded HashMap entries without validation, rate limiting, or size constraints, combined with a broken cleanup mechanism that retains malicious entries indefinitely.

## Finding Description

The vulnerability exists in the JWK consensus per-key mode implementation within the `KeyLevelConsensusManager`. When a validator receives a `KeyLevelObservationRequest` from a peer, the `process_peer_request()` method unconditionally creates HashMap entries using the `.entry().or_default()` pattern without bounds checking. [1](#0-0) 

This creates a new `ConsensusState::NotStarted` entry for every unique (issuer, kid) pair received, regardless of legitimacy. Although the function returns early for `NotStarted` states without sending a response, the HashMap entry persists in memory. [2](#0-1) 

The `states_by_key` field is an unbounded HashMap with no size constraints. [3](#0-2) 

Both `Issuer` and `KID` types are defined as unbounded `Vec<u8>` with no maximum size limits. [4](#0-3) 

**Cleanup Mechanism Failure:**

The `reset_with_on_chain_state()` method attempts cleanup but contains a critical logic bug. When an issuer doesn't exist in either the new on-chain state or the cached state (i.e., a bogus/malicious issuer), both `unwrap_or_default()` calls return `0` (the default for `u64`). The retain predicate evaluates to `0 == 0` (true), causing invalid entries to be retained instead of removed. [5](#0-4) 

**No Request Validation:**

The epoch manager forwards RPC requests without validating the (issuer, kid) contents—only the epoch number is checked. [6](#0-5) 

The (issuer, kid) pair is not validated against configured OIDC providers or any whitelist.

**No Rate Limiting:**

While channel size limits exist (100 for RPC routing), these only limit queued messages, not the rate of HashMap entry creation or the total number of entries. [7](#0-6) 

**Attack Flow:**
1. Byzantine validator crafts millions of unique `KeyLevelObservationRequest` messages with random (issuer, kid) pairs
2. Messages are forwarded through the network and epoch manager without validation
3. Each call to `process_peer_request()` creates a new HashMap entry via `.entry().or_default()`
4. The function returns early, but entries persist in `states_by_key`
5. Memory grows linearly with unique pairs until OOM occurs
6. Cleanup mechanism fails to remove bogus entries due to the `0 == 0` bug
7. Validator nodes crash, degrading network performance

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos Bug Bounty program criteria, specifically under the "Validator Node Slowdowns (High)" category which includes "DoS through resource exhaustion".

**Impact:**
1. **Validator Node Crashes**: Memory exhaustion leads to OOM conditions and validator process termination
2. **Network Availability Impact**: Multiple simultaneous validator crashes degrade network consensus performance
3. **Low Barrier to Attack**: A single Byzantine validator (< 1/3 stake requirement) can execute the attack
4. **Protocol-Level Vulnerability**: Root cause is implementation bugs (missing bounds checking + broken cleanup logic), not pure network flooding

The attack exploits specific code flaws rather than overwhelming network bandwidth, making it a protocol-level vulnerability rather than a network DoS attack.

## Likelihood Explanation

**Likelihood: High**

- **Attacker Requirements**: Single Byzantine validator with network access (within Aptos threat model of up to 1/3 Byzantine)
- **Complexity**: Trivial—generate random byte arrays for (issuer, kid) and send `KeyLevelObservationRequest` messages
- **Detection**: No validation checks on incoming (issuer, kid) parameters
- **Cost**: Minimal computational cost for attacker (message serialization), significant memory cost for victims
- **Persistence**: The cleanup bug ensures malicious entries persist across epoch state resets
- **Execution**: Can be executed continuously with automated scripts

The vulnerability is trivially exploitable because:
1. No authentication required for the (issuer, kid) values
2. No bounds checking on HashMap size
3. Cleanup mechanism fails to remove bogus entries
4. Attack can continue indefinitely until validators crash

## Recommendation

1. **Add HashMap Size Limits**: Implement a maximum size constraint for `states_by_key` HashMap
2. **Validate Against OIDC Providers**: Check that (issuer, kid) pairs match configured OIDC providers before creating entries
3. **Fix Cleanup Logic**: Modify `reset_with_on_chain_state()` to explicitly remove entries where the issuer doesn't exist in the new on-chain state:

```rust
self.states_by_key.retain(|(issuer, _), _| {
    let new_version = new_onchain_jwks.get(issuer).map(|jwks| jwks.version);
    let old_version = self.onchain_jwks.get(issuer).map(|jwks| jwks.version);
    
    // Only retain if issuer exists in new state AND versions match
    matches!((new_version, old_version), (Some(nv), Some(ov)) if nv == ov)
});
```

4. **Implement Per-Peer Rate Limiting**: Add rate limiting for RPC requests per peer to prevent flooding
5. **Add Size Constraints**: Define maximum sizes for `Issuer` and `KID` types

## Proof of Concept

While a full PoC would require setting up a validator network, the vulnerability can be demonstrated by examining the code flow:

1. A Byzantine validator sends multiple RPC messages with unique (issuer, kid) pairs
2. Each message triggers `process_peer_request()` which calls `.entry().or_default()`
3. The HashMap grows without bounds as new entries are created
4. When `reset_with_on_chain_state()` is called, bogus entries are retained due to the `0 == 0` comparison
5. Memory continues to grow until OOM occurs

The vulnerability is confirmed by code inspection showing the absence of validation, bounds checking, and the broken cleanup predicate.

## Notes

This vulnerability only affects validators when JWK consensus is enabled via the on-chain `JWKConsensusConfig` or the `JWK_CONSENSUS` feature flag. The per-key mode is controlled by the `JWK_CONSENSUS_PER_KEY_MODE` feature flag. [8](#0-7) 

The vulnerability represents a protocol-level implementation flaw rather than a pure network DoS attack, as it exploits specific bugs in the HashMap management and cleanup logic.

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

**File:** crates/aptos-jwk-consensus/src/epoch_manager.rs (L94-105)
```rust
    fn process_rpc_request(
        &mut self,
        peer_id: Author,
        rpc_request: IncomingRpcRequest,
    ) -> Result<()> {
        if Some(rpc_request.msg.epoch()) == self.epoch_state.as_ref().map(|s| s.epoch) {
            if let Some(tx) = &self.jwk_rpc_msg_tx {
                let _ = tx.push(peer_id, (peer_id, rpc_request));
            }
        }
        Ok(())
    }
```

**File:** crates/aptos-jwk-consensus/src/epoch_manager.rs (L222-222)
```rust
            let (jwk_rpc_msg_tx, jwk_rpc_msg_rx) = aptos_channel::new(QueueStyle::FIFO, 100, None);
```

**File:** crates/aptos-jwk-consensus/src/epoch_manager.rs (L228-228)
```rust
                if features.is_enabled(FeatureFlag::JWK_CONSENSUS_PER_KEY_MODE) {
```
