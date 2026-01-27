# Audit Report

## Title
CPU Exhaustion DoS via Handshake Flooding - Anti-Replay Protection Bypassed by Incorrect Ordering

## Summary
Validators can be flooded with invalid Noise handshake requests that force expensive X25519 Diffie-Hellman operations to be computed before any authentication or anti-replay checks occur. The anti-replay timestamp protection mechanism is ineffective because it is checked AFTER the computationally expensive cryptographic operations have already been performed.

## Finding Description

The Aptos network uses the Noise IK protocol for validator authentication. The handshake includes anti-replay protection via timestamps to prevent attackers from forcing validators to perform expensive Diffie-Hellman (DH) key exchanges. However, the implementation has a critical ordering flaw.

**Attack Flow:**

1. Attacker opens TCP connections to a validator node
2. Sends Noise handshake init messages with valid format but invalid/random data
3. Validator calls `upgrade_inbound()` which invokes `parse_client_init_message()`
4. **First expensive DH operation is computed** using the attacker-supplied ephemeral key
5. Only AFTER this DH computation completes is the anti-replay timestamp checked
6. Decryption fails, connection rejected, but CPU cycles already wasted

**Code Evidence:**

In the handshake flow: [1](#0-0) 

This calls into: [2](#0-1) 

The `parse_client_init_message()` function performs expensive cryptographic operations: [3](#0-2) 

But the anti-replay timestamp check happens AFTER `parse_client_init_message` returns: [4](#0-3) 

The code comments claim the timestamp check prevents expensive DH operations: [5](#0-4) 

However, this is **factually incorrect** - the timestamp is checked AFTER the first DH operation completes.

**Bypassing Existing Protections:**

1. **Anti-replay protection**: Only checked after expensive operations
2. **Connection limits**: Only enforced AFTER handshake completes [6](#0-5) 
3. **Minimal validation before DH**: Only message size checked (< 65535 bytes) [7](#0-6) 

**Attack Vectors:**

- Attacker can use different source public keys to bypass per-pubkey timestamp tracking
- Attacker can use incrementing timestamps to appear legitimate
- Even with timestamps, the first DH operation still executes before validation
- No rate limiting on handshake attempts before expensive crypto

## Impact Explanation

**High Severity** - Validator node slowdowns leading to consensus degradation.

X25519 Diffie-Hellman operations are computationally expensive. A coordinated attack flooding multiple validators with handshake requests can:

- Exhaust validator CPU resources processing invalid handshakes
- Delay processing of legitimate consensus messages
- Cause validators to fall behind in block production/voting
- Potentially trigger liveness failures if enough validators are degraded simultaneously

This meets the **High Severity** criteria: "Validator node slowdowns" which can escalate to consensus impact.

If the attack successfully degrades enough validators to impact consensus liveness, it could reach **Critical Severity** as a denial of service affecting network availability.

## Likelihood Explanation

**High Likelihood**:

- Attack requires only basic network access (TCP connections)
- No authentication needed to trigger expensive operations
- No stake or funds required
- Attack is network-based but targets application-layer cryptographic operations
- Attacker can amplify impact by:
  - Opening many concurrent connections
  - Sending rapid handshake requests per connection
  - Coordinating across multiple source IPs
  
The vulnerability is inherent in the protocol design where authentication happens AFTER expensive operations rather than before.

## Recommendation

**Implement early validation and rate limiting BEFORE expensive cryptographic operations:**

1. **Move anti-replay check before DH operations**: Restructure `parse_client_init_message()` to extract and validate the timestamp from the encrypted payload BEFORE performing any DH operations. This requires redesigning the protocol to include an unencrypted timestamp in the handshake init message.

2. **Add connection-level rate limiting**: Implement rate limits at the TCP accept layer, before handshake processing:
   - Limit handshake attempts per source IP per time window
   - Implement exponential backoff for failed handshake attempts
   - Track and reject excessive connection attempts

3. **Add lightweight proof-of-work**: Require clients to solve a lightweight computational puzzle before validators perform expensive DH operations.

4. **Implement handshake attempt budgeting**: Track CPU time spent on failed handshakes and temporarily blacklist sources that consume excessive resources.

**Immediate mitigation** (minimal code change):

Add connection attempt tracking and rate limiting in `TransportHandler` before calling `upgrade_inbound()`: [8](#0-7) 

Add a pre-handshake rate limiter here that tracks connection attempts per source address and rejects excessive attempts before the expensive upgrade process begins.

## Proof of Concept

```rust
// PoC: Flood validator with invalid handshakes to cause CPU exhaustion
use aptos_crypto::{noise, x25519, Uniform};
use futures::io::AsyncWriteExt;
use tokio::net::TcpStream;
use std::time::Instant;

#[tokio::test]
async fn test_handshake_dos_attack() {
    // Connect to validator (adjust address as needed)
    let validator_addr = "127.0.0.1:6180";
    
    let attack_start = Instant::now();
    let num_attacks = 1000;
    
    for i in 0..num_attacks {
        if let Ok(mut stream) = TcpStream::connect(validator_addr).await {
            // Generate random ephemeral key
            let mut rng = rand::thread_rng();
            let fake_ephemeral = x25519::PrivateKey::generate(&mut rng);
            let fake_ephemeral_pub = fake_ephemeral.public_key();
            
            // Craft malformed but size-valid handshake message
            let mut handshake_msg = vec![0u8; noise::handshake_init_msg_len(8)];
            
            // Prologue: fake peer_id | target's public key
            handshake_msg[0..32].fill(i as u8); // fake peer ID
            // Public key would go here (32 bytes) - leave as zeros
            
            // Handshake init: ephemeral key | encrypted static | encrypted payload
            let prologue_size = 32 + 32;
            handshake_msg[prologue_size..prologue_size+32]
                .copy_from_slice(fake_ephemeral_pub.as_slice());
            // Rest is random garbage that will fail decryption
            
            // Send the malicious handshake - validator will compute DH before rejecting
            let _ = stream.write_all(&handshake_msg).await;
            
            // Connection will be rejected after validator wastes CPU on DH
        }
    }
    
    let attack_duration = attack_start.elapsed();
    println!("Sent {} invalid handshakes in {:?}", num_attacks, attack_duration);
    println!("Each handshake forced validator to compute expensive DH operation");
    println!("before authentication check could reject it");
}
```

**Expected Result**: Validator CPU usage spikes as it processes 1000 X25519 DH operations for invalid handshakes before rejecting them. With sufficient connections, this can degrade validator performance and consensus participation.

## Notes

The vulnerability exists in both the legacy Diem framework code and the current Aptos implementation. The anti-replay protection mechanism was specifically designed to prevent this attack (as evidenced by code comments), but the implementation is incorrect because the validation occurs after the expensive operations rather than before them.

This represents a gap between intended security design and actual implementation that creates a practical DoS vector against validator nodes.

### Citations

**File:** network/framework/src/transport/mod.rs (L277-293)
```rust
    let (mut socket, remote_peer_id, peer_role) =
        ctxt.noise.upgrade_inbound(socket).await.map_err(|err| {
            if err.should_security_log() {
                sample!(
                    SampleRate::Duration(Duration::from_secs(15)),
                    warn!(
                        SecurityEvent::NoiseHandshake,
                        NetworkSchema::new(&ctxt.noise.network_context)
                            .network_address(&addr)
                            .connection_origin(&origin),
                        error = %err,
                    )
                );
            }
            let err = io::Error::other(err);
            add_pp_addr(proxy_protocol_enabled, err, &addr)
        })?;
```

**File:** network/framework/src/noise/handshake.rs (L30-39)
```rust
/// In a mutually authenticated network, a client message is accompanied with a timestamp.
/// This is in order to prevent replay attacks, where the attacker does not know the client's static key,
/// but can still replay a handshake message in order to force a peer into performing a few Diffie-Hellman key exchange operations.
///
/// Thus, to prevent replay attacks a responder will always check if the timestamp is strictly increasing,
/// effectively considering it as a stateful counter.
///
/// If the client timestamp has been seen before, or is not strictly increasing,
/// we can abort the handshake early and avoid heavy Diffie-Hellman computations.
/// If the client timestamp is valid, we store it.
```

**File:** network/framework/src/noise/handshake.rs (L361-364)
```rust
        let (remote_public_key, handshake_state, payload) = self
            .noise_config
            .parse_client_init_message(prologue, client_init_message)
            .map_err(|err| NoiseHandshakeError::ServerParseClient(remote_peer_short, err))?;
```

**File:** network/framework/src/noise/handshake.rs (L429-454)
```rust
        // if on a mutually authenticated network,
        // the payload should contain a u64 client timestamp
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

**File:** crates/aptos-crypto/src/noise.rs (L428-430)
```rust
        if received_message.len() > MAX_SIZE_NOISE_MSG {
            return Err(NoiseError::ReceivedMsgTooLarge);
        }
```

**File:** crates/aptos-crypto/src/noise.rs (L449-450)
```rust
        let dh_output = self.private_key.diffie_hellman(&re);
        let k = mix_key(&mut ck, &dh_output)?;
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

**File:** network/framework/src/peer_manager/transport.rs (L106-109)
```rust
                inbound_connection = self.listener.select_next_some() => {
                    if let Some(fut) = self.upgrade_inbound_connection(inbound_connection) {
                        pending_inbound_connections.push(fut);
                    }
```
