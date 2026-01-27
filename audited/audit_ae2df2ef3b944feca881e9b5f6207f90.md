# Audit Report

## Title
Anti-Replay Timestamp Poisoning via Unbounded Future Timestamps Causing Permanent Validator DoS

## Summary
The `AntiReplayTimestamps` implementation in the Noise handshake protocol lacks validation for unreasonably large future timestamps. An attacker with temporary access to authenticate (via key compromise, authentication bug, or misconfiguration) can send a handshake with timestamp = `u64::MAX`, permanently preventing legitimate connections from that peer by poisoning the anti-replay timestamp storage.

## Finding Description

The anti-replay timestamp mechanism is designed to prevent replay attacks during Noise protocol handshakes in mutual authentication mode. However, the implementation has a critical flaw: it only validates that timestamps are strictly increasing, without checking if timestamps are reasonable or within bounds of current time. [1](#0-0) 

The `is_replay()` function only checks if the new timestamp is less than or equal to the previously stored timestamp, but does NOT validate that the timestamp is close to current time or within any reasonable bound.

During handshake processing, the timestamp is stored BEFORE the connection is fully established and BEFORE PeerManager determines if the connection will be accepted: [2](#0-1) 

The timestamp is stored at line 453, but the connection could still fail during:
- Server response construction (lines 456-464)
- Socket write operations (lines 472-475)  
- PeerManager validation and connection limit checks (lines 351-389 in peer_manager/mod.rs) [3](#0-2) 

**Attack Scenario:**

1. Attacker gains temporary access to a trusted peer's credentials (via compromise, bug, or misconfiguration)
2. Attacker sends a handshake message with `client_timestamp = u64::MAX` (or any arbitrarily large future value)
3. The timestamp check passes (line 445) because `u64::MAX > any_previous_timestamp`
4. The malicious timestamp is stored (line 453)
5. Even if the connection is later rejected by PeerManager or fails for other reasons, the timestamp persists
6. All future legitimate handshakes from that peer with actual current timestamps will fail the replay check because `current_time < u64::MAX`
7. The peer is permanently unable to establish connections until the validator restarts (no garbage collection exists) [4](#0-3) 

The `store_timestamp()` function unconditionally overwrites with the new timestamp, and there is no garbage collection or expiry mechanism to remove poisoned timestamps.

This violates the **Network Availability** and **Validator Connectivity** invariants. The codebase explicitly acknowledges the lack of garbage collection: [5](#0-4) 

While the comment suggests this is acceptable due to bounded trusted peer sets, it overlooks the timestamp poisoning attack vector.

## Impact Explanation

**Severity: High** (Validator node disruption/significant protocol violation)

This vulnerability enables **permanent Denial of Service** against validator-to-validator connectivity:

- **Validator Network Disruption**: An attacker who temporarily compromises a validator's private key can permanently prevent that validator from connecting to other validators, even after the compromise is detected and mitigated
- **Consensus Liveness Impact**: If multiple validators are affected, the network could lose consensus liveness if the affected validators cannot participate
- **Persistent Attack**: The poisoned timestamp persists indefinitely (until node restart) due to lack of garbage collection
- **No Recovery Path**: There is no mechanism to clear or expire poisoned timestamps

The impact qualifies as High severity under Aptos Bug Bounty criteria: "Validator node slowdowns" and "Significant protocol violations". While not directly causing consensus safety violations, it can degrade network performance and availability.

## Likelihood Explanation

**Likelihood: Medium-High**

The attack requires one of the following conditions:
1. **Temporary key compromise**: Attacker gains brief access to a validator's x25519 private key
2. **Authentication bug**: A bug in the handshake authentication allows unauthorized handshakes to pass temporarily
3. **Misconfiguration**: Incorrect trusted peer set configuration temporarily allows malicious peers
4. **Insider threat**: Malicious validator operator intentionally poisons timestamps of other validators

While requiring elevated access, such scenarios occur in practice:
- Private keys can be temporarily compromised via memory dumps, side channels, or supply chain attacks
- Authentication bugs are discovered periodically in cryptographic protocol implementations
- The attack only needs to succeed ONCE to cause permanent damage
- The lack of defense-in-depth makes the system fragile to any authentication bypass

## Recommendation

Implement timestamp bounds validation similar to the Move framework's transaction validation:

```rust
impl AntiReplayTimestamps {
    // Maximum acceptable future drift: 60 seconds (in milliseconds)
    const MAX_FUTURE_DRIFT_MS: u64 = 60_000;
    
    /// Returns true if the timestamp is a replay OR unreasonably far in the future
    pub fn is_replay_or_invalid(&self, pubkey: x25519::PublicKey, timestamp: u64) -> bool {
        // Check for replay (timestamp not strictly increasing)
        if let Some(last_timestamp) = self.0.get(&pubkey) {
            if &timestamp <= last_timestamp {
                return true;
            }
        }
        
        // Check for unreasonable future timestamp
        let now: u64 = duration_since_epoch().as_millis() as u64;
        if timestamp > now.saturating_add(Self::MAX_FUTURE_DRIFT_MS) {
            return true;  // Timestamp too far in future
        }
        
        false
    }
}
```

Update the handshake validation to use the new function: [6](#0-5) 

Additionally, implement periodic garbage collection to remove stale entries older than a reasonable threshold (e.g., 24 hours), similar to the patterns in: [7](#0-6) 

## Proof of Concept

```rust
#[test]
fn test_future_timestamp_dos_attack() {
    use crate::noise::handshake::{AntiReplayTimestamps, HandshakeAuthMode, NoiseUpgrader};
    use aptos_crypto::{test_utils::TEST_SEED, x25519, Uniform};
    use aptos_memsocket::MemorySocket;
    use futures::{executor::block_on, future::join};
    use rand::SeedableRng;

    // Setup validator peers with mutual auth
    let mut rng = ::rand::rngs::StdRng::from_seed(TEST_SEED);
    let (client_private_key, client_public_key) = (
        x25519::PrivateKey::generate(&mut rng),
        x25519::PrivateKey::generate(&mut rng).public_key(),
    );
    let (server_private_key, _) = (
        x25519::PrivateKey::generate(&mut rng),
        x25519::PrivateKey::generate(&mut rng).public_key(),
    );

    let peers_and_metadata = /* setup as in test_timestamp_replay */;
    
    let client = NoiseUpgrader::new(
        client_network_context,
        client_private_key,
        HandshakeAuthMode::mutual(peers_and_metadata.clone()),
    );
    let server = NoiseUpgrader::new(
        server_network_context,
        server_private_key,
        HandshakeAuthMode::mutual(peers_and_metadata),
    );

    // Step 1: Attacker sends handshake with MAX timestamp (DoS attack)
    let malicious_timestamp = || u64::MAX.to_le_bytes();
    
    let (dialer_socket, listener_socket) = MemorySocket::new_pair();
    let (client_res, server_res) = block_on(join(
        client.upgrade_outbound(
            dialer_socket,
            server.network_context.peer_id(),
            server_public_key,
            malicious_timestamp,
        ),
        server.upgrade_inbound(listener_socket),
    ));

    // The malicious handshake completes successfully
    assert!(client_res.is_ok());
    assert!(server_res.is_ok());

    // Step 2: Legitimate handshake with current timestamp FAILS
    let current_timestamp = || AntiReplayTimestamps::now();
    
    let (dialer_socket2, listener_socket2) = MemorySocket::new_pair();
    let (client_res2, server_res2) = block_on(join(
        client.upgrade_outbound(
            dialer_socket2,
            server.network_context.peer_id(),
            server_public_key,
            current_timestamp,
        ),
        server.upgrade_inbound(listener_socket2),
    ));

    // Legitimate connection is rejected as "replay" because current_time < u64::MAX
    assert!(server_res2.is_err());
    assert!(matches!(
        server_res2.unwrap_err(),
        NoiseHandshakeError::ServerReplayDetected(_, _)
    ));
    
    // Validator is now permanently DoS'd from accepting connections from this peer
}
```

**Notes:**

This vulnerability demonstrates a critical defense-in-depth failure where the network layer lacks timestamp validation present in the transaction layer. The attack requires elevated access but causes disproportionate permanent damage. The fix is straightforward: add timestamp bounds checking consistent with security best practices used elsewhere in the codebase.

### Citations

**File:** network/framework/src/noise/handshake.rs (L57-65)
```rust
    /// Returns true if the timestamp has already been observed for this peer
    /// or if it's an old timestamp
    pub fn is_replay(&self, pubkey: x25519::PublicKey, timestamp: u64) -> bool {
        if let Some(last_timestamp) = self.0.get(&pubkey) {
            &timestamp <= last_timestamp
        } else {
            false
        }
    }
```

**File:** network/framework/src/noise/handshake.rs (L67-73)
```rust
    /// Stores the timestamp
    pub fn store_timestamp(&mut self, pubkey: x25519::PublicKey, timestamp: u64) {
        self.0
            .entry(pubkey)
            .and_modify(|last_timestamp| *last_timestamp = timestamp)
            .or_insert(timestamp);
    }
```

**File:** network/framework/src/noise/handshake.rs (L86-91)
```rust
        // Only use anti replay protection in mutual-auth scenarios. In theory,
        // this is applicable everywhere; however, we would need to spend some
        // time making this more sophisticated so it garbage collects old
        // timestamps and doesn't use unbounded space. These are not problems in
        // mutual-auth scenarios because we have a bounded set of trusted peers
        // that rarely changes.
```

**File:** network/framework/src/noise/handshake.rs (L443-454)
```rust
            // check the timestamp is not a replay
            let mut anti_replay_timestamps = anti_replay_timestamps.write();
            if anti_replay_timestamps.is_replay(remote_public_key, client_timestamp) {
                return Err(NoiseHandshakeError::ServerReplayDetected(
                    remote_peer_short,
                    client_timestamp,
                ));
            }

            // store the timestamp
            anti_replay_timestamps.store_timestamp(remote_public_key, client_timestamp);
        }
```

**File:** network/framework/src/peer_manager/mod.rs (L351-389)
```rust
        // Verify that we have not reached the max connection limit for unknown inbound peers
        if conn.metadata.origin == ConnectionOrigin::Inbound {
            // Everything below here is meant for unknown peers only. The role comes from
            // the Noise handshake and if it's not `Unknown` then it is trusted.
            if conn.metadata.role == PeerRole::Unknown {
                // TODO: Keep track of somewhere else to not take this hit in case of DDoS
                // Count unknown inbound connections
                let unknown_inbound_conns = self
                    .active_peers
                    .iter()
                    .filter(|(peer_id, (metadata, _))| {
                        metadata.origin == ConnectionOrigin::Inbound
                            && trusted_peers
                                .get(peer_id)
                                .is_none_or(|peer| peer.role == PeerRole::Unknown)
                    })
                    .count();

                // Reject excessive inbound connections made by unknown peers
                // We control outbound connections with Connectivity manager before we even send them
                // and we must allow connections that already exist to pass through tie breaking.
                if !self
                    .active_peers
                    .contains_key(&conn.metadata.remote_peer_id)
                    && unknown_inbound_conns + 1 > self.inbound_connection_limit
                {
                    info!(
                        NetworkSchema::new(&self.network_context)
                            .connection_metadata_with_address(&conn.metadata),
                        "{} Connection rejected due to connection limit: {}",
                        self.network_context,
                        conn.metadata
                    );
                    counters::connections_rejected(&self.network_context, conn.metadata.origin)
                        .inc();
                    self.disconnect(conn);
                    return;
                }
            }
```

**File:** aptos-move/framework/aptos-framework/sources/nonce_validation.move (L177-193)
```text
        // Garbage collect upto MAX_ENTRIES_GARBAGE_COLLECTED_PER_CALL expired nonces in the bucket.
        let i = 0;
        while (i < MAX_ENTRIES_GARBAGE_COLLECTED_PER_CALL && !bucket.nonces_ordered_by_exp_time.is_empty()) {
            let (front_k, _) = bucket.nonces_ordered_by_exp_time.borrow_front();
            // We garbage collect a nonce after it has expired and the NONCE_REPLAY_PROTECTION_OVERLAP_INTERVAL_SECONDS
            // seconds have passed.
            if (front_k.txn_expiration_time + NONCE_REPLAY_PROTECTION_OVERLAP_INTERVAL_SECONDS < current_time) {
                bucket.nonces_ordered_by_exp_time.pop_front();
                bucket.nonce_to_exp_time_map.remove(&NonceKey {
                    sender_address: front_k.sender_address,
                    nonce: front_k.nonce,
                });
            } else {
                break;
            };
            i = i + 1;
        };
```
