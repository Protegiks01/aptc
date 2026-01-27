# Audit Report

## Title
Permanent Validator Connection Lockout Due to Clock Skew in Anti-Replay Timestamp Validation

## Summary
The network handshake's anti-replay timestamp mechanism lacks absolute time validation, allowing peers with significant clock skew to permanently lock themselves out from connecting to other validators. A validator with a clock ahead by N time units will store a future timestamp, and subsequent reconnection attempts after clock correction will be permanently rejected as replay attacks until real time catches up.

## Finding Description

The `AntiReplayTimestamps` system in the Noise handshake protocol enforces strictly increasing timestamps per peer to prevent replay attacks. However, it fails to validate whether timestamps are within a reasonable bound from the current time. [1](#0-0) 

The timestamp validation only checks relative ordering (strictly increasing per peer), not absolute validity: [2](#0-1) 

**Attack Path:**

1. Validator A's system clock has significant positive skew (+1 year due to NTP attack, hardware fault, or misconfiguration)
2. Validator A initiates connection to Validator B using `AntiReplayTimestamps::now()` which generates timestamp = current_system_time + 1_year
3. Validator B validates the handshake:
   - Checks timestamp length: ✓
   - Calls `is_replay()`: Returns false (first connection from this key)
   - Stores the future timestamp in the HashMap permanently
4. Connection succeeds
5. Validator A fixes their clock to correct time
6. Validator A attempts to reconnect (or auto-reconnects via `ConnectivityManager`)
7. New timestamp = correct_current_time (which is < stored_future_timestamp)
8. Validator B's `is_replay()` check: `new_timestamp <= stored_timestamp` returns true
9. Handshake fails with `ServerReplayDetected` error
10. **All future reconnection attempts fail indefinitely** because:
    - Each retry generates a fresh timestamp with current time
    - The stored future timestamp never expires or resets
    - There is no garbage collection mechanism [3](#0-2) 

This contrasts sharply with consensus block validation, which enforces a 5-minute TIMEBOUND for timestamps: [4](#0-3) 

The network layer has no equivalent protection.

## Impact Explanation

**Severity: Medium to High**

This vulnerability qualifies as **Medium severity** per the Aptos bug bounty criteria ("State inconsistencies requiring intervention") with potential escalation to **High** or **Critical** severity depending on scope:

- **Single Validator Pair**: Permanent connection failure between two validators requires manual intervention (node restart). Medium severity.
- **Multiple Validators**: If clock skew affects multiple validators in a validator network with mutual authentication, this could prevent quorum formation, leading to consensus liveness failure. High to Critical severity.
- **Recovery Difficulty**: The only recovery options are:
  1. Wait for real time to catch up (could be months/years)
  2. Manually restart the listening validator (clears in-memory state)
  3. Rotate the affected validator's public key (requires governance action)

The issue violates the **Consensus Safety** invariant (#2) by potentially preventing < 2/3 of validators from maintaining connectivity necessary for consensus.

## Likelihood Explanation

**Likelihood: Medium**

Clock skew is a realistic scenario that occurs in production systems:

1. **NTP Failures**: Network Time Protocol synchronization issues are common
2. **Hardware Faults**: CMOS battery failures, faulty real-time clocks
3. **Virtualization Issues**: VM time drift, hypervisor clock skew
4. **Timezone Bugs**: Incorrect timezone configuration
5. **Malicious Attacks**: NTP spoofing or man-in-the-middle attacks
6. **Manual Misconfiguration**: Administrators accidentally setting wrong time

The vulnerability is triggered automatically upon the first successful connection with skewed clock, requiring no sophisticated attack. The `setup_network()` function uses `TimeService::real()` which directly reads system time: [5](#0-4) 

## Recommendation

Implement absolute time validation with a configurable tolerance window (similar to consensus TIMEBOUND):

```rust
impl AntiReplayTimestamps {
    // Allow 5 minutes of clock drift tolerance (matching consensus TIMEBOUND)
    const MAX_TIMESTAMP_DRIFT_MS: u64 = 5 * 60 * 1000; // 5 minutes in milliseconds
    
    /// Validates that timestamp is within acceptable bounds
    pub fn is_valid_timestamp(&self, timestamp: u64) -> bool {
        let now = duration_since_epoch().as_millis() as u64;
        
        // Reject timestamps too far in the past (> 5 minutes old)
        if timestamp + Self::MAX_TIMESTAMP_DRIFT_MS < now {
            return false;
        }
        
        // Reject timestamps too far in the future (> 5 minutes ahead)
        if timestamp > now + Self::MAX_TIMESTAMP_DRIFT_MS {
            return false;
        }
        
        true
    }
    
    /// Returns true if the timestamp has already been observed for this peer
    /// or if it's an old timestamp or outside acceptable time bounds
    pub fn is_replay(&self, pubkey: x25519::PublicKey, timestamp: u64) -> bool {
        // First check absolute validity
        if !self.is_valid_timestamp(timestamp) {
            return true; // Treat invalid timestamps as replays
        }
        
        // Then check relative ordering
        if let Some(last_timestamp) = self.0.get(&pubkey) {
            &timestamp <= last_timestamp
        } else {
            false
        }
    }
}
```

Additionally, implement periodic garbage collection of old timestamps to prevent unbounded memory growth:

```rust
pub fn gc_old_timestamps(&mut self, max_age_ms: u64) {
    let now = duration_since_epoch().as_millis() as u64;
    self.0.retain(|_, &mut timestamp| {
        now.saturating_sub(timestamp) <= max_age_ms
    });
}
```

## Proof of Concept

```rust
#[test]
fn test_clock_skew_lockout() {
    use crate::noise::handshake::{AntiReplayTimestamps, NoiseUpgrader, HandshakeAuthMode};
    use aptos_memsocket::MemorySocket;
    use futures::{executor::block_on, future::join};
    
    // Build peers with mutual authentication
    let ((client, _), (server, server_public_key)) = build_peers(true, None);
    let server_peer_id = server.network_context.peer_id();
    
    // Simulate clock skew: client clock is 1 year in the future
    let one_year_ms = 365 * 24 * 60 * 60 * 1000_u64;
    let future_timestamp = move || {
        let now: u64 = duration_since_epoch().as_millis() as u64;
        (now + one_year_ms).to_le_bytes()
    };
    
    // First connection with skewed clock succeeds
    let (dialer_socket, listener_socket) = MemorySocket::new_pair();
    let (client_result, server_result) = block_on(join(
        client.upgrade_outbound(
            dialer_socket,
            server_peer_id,
            server_public_key,
            future_timestamp,
        ),
        server.upgrade_inbound(listener_socket),
    ));
    
    assert!(client_result.is_ok(), "First connection should succeed");
    assert!(server_result.is_ok(), "First connection should succeed");
    
    // Client fixes their clock, tries to reconnect with correct time
    let (dialer_socket2, listener_socket2) = MemorySocket::new_pair();
    let (client_result2, server_result2) = block_on(join(
        client.upgrade_outbound(
            dialer_socket2,
            server_peer_id,
            server_public_key,
            AntiReplayTimestamps::now, // Now using correct time
        ),
        server.upgrade_inbound(listener_socket2),
    ));
    
    // Reconnection FAILS due to stored future timestamp
    assert!(client_result2.is_err(), "Reconnection should fail");
    assert!(server_result2.is_err(), "Server should reject as replay");
    
    // Verify it's specifically a ServerReplayDetected error
    match server_result2.unwrap_err() {
        NoiseHandshakeError::ServerReplayDetected(_, _) => {
            // Expected: permanent lockout until real time catches up
        },
        other => panic!("Expected ServerReplayDetected, got {:?}", other),
    }
}
```

This test demonstrates that once a future timestamp is stored, the validator is permanently locked out from reconnecting until real time advances to match the stored timestamp—a condition that could take months or years to resolve naturally.

### Citations

**File:** network/framework/src/noise/handshake.rs (L40-74)
```rust
#[derive(Default)]
pub struct AntiReplayTimestamps(HashMap<x25519::PublicKey, u64>);

impl AntiReplayTimestamps {
    /// The timestamp is sent as a payload, so that it is encrypted.
    /// Note that a millisecond value is a 16-byte value in rust,
    /// but as we use it to store a duration since UNIX_EPOCH we will never use more than 8 bytes.
    pub const TIMESTAMP_SIZE: usize = 8;

    /// obtain the current timestamp
    pub fn now() -> [u8; Self::TIMESTAMP_SIZE] {
        let now: u64 = duration_since_epoch().as_millis() as u64; // (TIMESTAMP_SIZE)

        // e.g. [157, 126, 253, 97, 114, 1, 0, 0]
        now.to_le_bytes()
    }

    /// Returns true if the timestamp has already been observed for this peer
    /// or if it's an old timestamp
    pub fn is_replay(&self, pubkey: x25519::PublicKey, timestamp: u64) -> bool {
        if let Some(last_timestamp) = self.0.get(&pubkey) {
            &timestamp <= last_timestamp
        } else {
            false
        }
    }

    /// Stores the timestamp
    pub fn store_timestamp(&mut self, pubkey: x25519::PublicKey, timestamp: u64) {
        self.0
            .entry(pubkey)
            .and_modify(|last_timestamp| *last_timestamp = timestamp)
            .or_insert(timestamp);
    }
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

**File:** network/framework/src/noise/handshake.rs (L431-454)
```rust
        if let Some(anti_replay_timestamps) = self.auth_mode.anti_replay_timestamps() {
            // check that the payload received as the client timestamp (in seconds)
            if payload.len() != AntiReplayTimestamps::TIMESTAMP_SIZE {
                return Err(NoiseHandshakeError::MissingAntiReplayTimestamp(
                    remote_peer_short,
                ));
            }

            let mut client_timestamp = [0u8; AntiReplayTimestamps::TIMESTAMP_SIZE];
            client_timestamp.copy_from_slice(&payload);
            let client_timestamp = u64::from_le_bytes(client_timestamp);

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

**File:** consensus/consensus-types/src/block.rs (L532-539)
```rust
            let current_ts = duration_since_epoch();

            // we can say that too far is 5 minutes in the future
            const TIMEBOUND: u64 = 300_000_000;
            ensure!(
                self.timestamp_usecs() <= (current_ts.as_micros() as u64).saturating_add(TIMEBOUND),
                "Blocks must not be too far in the future"
            );
```

**File:** network/builder/src/dummy.rs (L107-107)
```rust
        TimeService::real(),
```
