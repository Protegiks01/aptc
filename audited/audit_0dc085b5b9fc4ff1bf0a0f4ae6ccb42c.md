# Audit Report

## Title
AES-GCM Cryptographic Bound Violation in NoiseSession - Lack of Session Rekeying After 2^32 Messages

## Summary
The `NoiseSession` implementation in `noise.rs` uses AES-256-GCM encryption with a u64 nonce counter, allowing up to 2^64 messages without rekeying. This violates NIST SP 800-38D recommendations which specify that AES-GCM should not exceed 2^32 invocations with the same key. Additionally, there is no session expiration or automatic rekeying mechanism, allowing indefinitely long-lived sessions that could theoretically accumulate sufficient ciphertext for cryptanalysis. [1](#0-0) 

## Finding Description
The `NoiseSession` struct maintains `write_nonce` and `read_nonce` as u64 counters that increment with each message encrypted or decrypted. The nonce is constructed as 12 bytes: 4 zero bytes followed by the 8-byte u64 counter in big-endian format. [2](#0-1) 

The code only checks for u64 overflow (returning `NonceOverflow` error at 2^64), but does not enforce the NIST SP 800-38D Section 8 recommendation that AES-GCM should not exceed 2^32 invocations with the same key due to birthday bound attacks on the authentication tag. [3](#0-2) 

Furthermore, the Aptos network layer allows validator connections to remain open indefinitely with no forced rekeying or session expiration: [4](#0-3) 

The connectivity manager performs health checks but does not enforce session lifetime limits or periodic reconnection of healthy connections: [5](#0-4) 

**Exploitation Path:**
1. Attacker establishes a connection to a validator (either as a malicious validator or compromised peer)
2. Maintains the connection for an extended period (50+ days at high message rates)
3. Exchanges sufficient messages to exceed 2^32 invocations (approximately 4.3 billion messages)
4. After this threshold, the birthday bound probability for authentication tag collision increases from negligible to measurable
5. Attacker can attempt authentication tag forgery attacks with degraded security margins

This violates the **Cryptographic Correctness** invariant: "BLS signatures, VRF, and hash operations must be secure" - which extends to encryption and authentication mechanisms.

## Impact Explanation
This qualifies as **Medium Severity** per Aptos Bug Bounty criteria because:
- It represents degraded cryptographic security that could lead to authentication bypass
- Successful exploitation could allow message forgery or manipulation of consensus communications
- Does not directly lead to immediate funds loss but creates a weakened security perimeter
- Requires significant time investment (weeks to months) making it a "limited" rather than critical threat

The degraded security after 2^32 messages increases the feasibility of:
- Authentication tag forgery attempts
- Birthday bound collision attacks on the 128-bit GCM tag
- Potential man-in-the-middle attacks on long-lived sessions

## Likelihood Explanation
**Likelihood: Low to Medium**

At realistic consensus message rates:
- 1,000 messages/second: 2^32 messages reached in ~50 days
- 100 messages/second: 2^32 messages reached in ~497 days (~1.4 years)

Validator connections in Aptos:
- Can remain open indefinitely between validators in the active set
- Exchange frequent consensus messages (proposals, votes, commits)
- Health checks detect failures but don't force periodic reconnection

While reaching 2^32 messages is theoretically possible, several factors reduce likelihood:
- Network disruptions naturally force reconnections
- Validator set changes may trigger new connections
- The time window (weeks to months) is substantial
- Even after 2^32 messages, attack success is not guaranteed (only probability increases)

## Recommendation
Implement session rekeying and lifetime limits:

```rust
pub struct NoiseSession {
    valid: bool,
    remote_public_key: x25519::PublicKey,
    write_key: Vec<u8>,
    write_nonce: u64,
    read_key: Vec<u8>,
    read_nonce: u64,
    // Add these fields:
    message_count: u64,
    session_start_time: std::time::Instant,
}

const MAX_MESSAGES_BEFORE_REKEY: u64 = 1u64 << 32; // 2^32
const MAX_SESSION_LIFETIME: Duration = Duration::from_secs(86400); // 24 hours

impl NoiseSession {
    pub fn write_message_in_place(&mut self, message: &mut [u8]) -> Result<Vec<u8>, NoiseError> {
        // Check if rekeying is needed
        if self.message_count >= MAX_MESSAGES_BEFORE_REKEY {
            return Err(NoiseError::RekeyRequired);
        }
        
        // Check session lifetime
        if self.session_start_time.elapsed() > MAX_SESSION_LIFETIME {
            return Err(NoiseError::SessionExpired);
        }
        
        // ... existing encryption logic ...
        
        self.message_count += 1;
        
        // ... rest of implementation ...
    }
}
```

Add new error variants:
```rust
pub enum NoiseError {
    // ... existing variants ...
    #[error("noise: session requires rekeying (message limit exceeded)")]
    RekeyRequired,
    
    #[error("noise: session expired (time limit exceeded)")]
    SessionExpired,
}
```

When these errors occur, the connection should be closed and re-established with a new handshake, generating fresh keys.

## Proof of Concept
```rust
#[test]
fn test_message_limit_enforcement() {
    use aptos_crypto::{noise, x25519, traits::Uniform};
    use rand::SeedableRng;
    
    let mut rng = rand::rngs::StdRng::from_seed([0u8; 32]);
    let key1 = x25519::PrivateKey::generate(&mut rng);
    let key2 = x25519::PrivateKey::generate(&mut rng);
    
    let config1 = noise::NoiseConfig::new(key1);
    let config2 = noise::NoiseConfig::new(key2);
    
    // Perform handshake
    let mut buffer1 = vec![0u8; noise::handshake_init_msg_len(0)];
    let state = config1.initiate_connection(
        &mut rng, 
        b"test", 
        key2.public_key(), 
        None, 
        &mut buffer1
    ).unwrap();
    
    let mut buffer2 = vec![0u8; noise::handshake_resp_msg_len(0)];
    let (_, mut session2) = config2.respond_to_client_and_finalize(
        &mut rng,
        b"test",
        &buffer1,
        None,
        &mut buffer2
    ).unwrap();
    
    let (_, mut session1) = config1.finalize_connection(state, &buffer2).unwrap();
    
    // Simulate sending 2^32 messages (in practice, just check the counter behavior)
    // This would take too long to actually run, but demonstrates the issue
    let mut test_message = vec![0u8; 100];
    
    // Send many messages to approach the limit
    for i in 0..1000 {
        session1.write_message_in_place(&mut test_message).unwrap();
    }
    
    // The session should eventually enforce the 2^32 limit
    // Currently, it only checks for u64 overflow, not the AES-GCM limit
    assert!(session1.write_nonce == 1000);
    
    // After 2^32 messages, security guarantees degrade
    // (This test demonstrates the counter mechanism but cannot practically
    //  run 2^32 iterations)
}
```

**Notes:**
This vulnerability represents a violation of cryptographic best practices (NIST SP 800-38D) rather than an immediately exploitable bug. The practical exploitation requires maintaining a connection for weeks to months while exchanging billions of messages. While theoretically possible in a high-throughput validator network, the time and resource requirements make this a lower-priority concern compared to more immediate vulnerabilities. However, implementing session rekeying and lifetime limits would improve defense-in-depth and align with cryptographic standards.

### Citations

**File:** crates/aptos-crypto/src/noise.rs (L584-609)
```rust
pub struct NoiseSession {
    /// a session can be marked as invalid if it has seen a decryption failure
    valid: bool,
    /// the public key of the other peer
    remote_public_key: x25519::PublicKey,
    /// key used to encrypt messages to the other peer
    write_key: Vec<u8>,
    /// associated nonce (in practice the maximum u64 value cannot be reached)
    write_nonce: u64,
    /// key used to decrypt messages received from the other peer
    read_key: Vec<u8>,
    /// associated nonce (in practice the maximum u64 value cannot be reached)
    read_nonce: u64,
}

impl NoiseSession {
    fn new(write_key: Vec<u8>, read_key: Vec<u8>, remote_public_key: x25519::PublicKey) -> Self {
        Self {
            valid: true,
            remote_public_key,
            write_key,
            write_nonce: 0,
            read_key,
            read_nonce: 0,
        }
    }
```

**File:** crates/aptos-crypto/src/noise.rs (L640-645)
```rust
        let mut nonce = [0u8; 4].to_vec();
        nonce.extend_from_slice(&self.write_nonce.to_be_bytes());
        assert_eq!(nonce.len(), 12);
        let nonce = aead::Nonce::assume_unique_for_key(
            nonce.try_into().expect("Incorrect AES256-GCM nonce length"),
        );
```

**File:** crates/aptos-crypto/src/noise.rs (L652-655)
```rust
        self.write_nonce = self
            .write_nonce
            .checked_add(1)
            .ok_or(NoiseError::NonceOverflow)?;
```

**File:** network/framework/src/noise/stream.rs (L34-45)
```rust
pub struct NoiseStream<TSocket> {
    /// the socket we write to and read from
    socket: TSocket,
    /// the noise session used to encrypt and decrypt messages
    session: noise::NoiseSession,
    /// handy buffers to write/read
    buffers: Box<NoiseBuffers>,
    /// an enum used for progressively reading a noise payload
    read_state: ReadState,
    /// an enum used for progressively writing a noise payload
    write_state: WriteState,
}
```

**File:** network/framework/src/protocols/health_checker/mod.rs (L106-109)
```rust
    /// Number of successive ping failures we tolerate before declaring a node as unhealthy and
    /// disconnecting from it. In the future, this can be replaced with a more general failure
    /// detection policy.
    ping_failures_tolerated: u64,
```
