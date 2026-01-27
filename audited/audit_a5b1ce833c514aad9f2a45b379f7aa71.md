# Audit Report

## Title
Byzantine Node Can Exhaust Validator Resources Through Unlimited RequestShare RPC Spam

## Summary
The `handle_incoming_msg()` function in `SecretShareManager` lacks rate limiting when responding to `RequestShare` RPC requests. A Byzantine validator node can repeatedly request the same secret share, causing resource exhaustion on victim nodes through unbounded queue growth, CPU exhaustion from lock contention, and network bandwidth consumption.

## Finding Description

The secret sharing protocol in Aptos consensus allows validators to request secret shares from peers for specific rounds. When a validator receives a `RequestShare` message, it immediately responds with the requested share without any rate limiting or deduplication mechanism. [1](#0-0) 

The vulnerability exists because:

1. **No Cryptographic Cost for RequestShare**: Unlike `Share` messages which require BLS signature verification, `RequestShare` messages have trivial verification (only epoch check): [2](#0-1) 

2. **Unbounded Verified Message Queue**: After passing trivial verification, messages are queued in an unbounded channel before processing: [3](#0-2) 

3. **No Request Deduplication**: The system doesn't track which peers have already received shares for a given round. Each request is processed independently, causing repeated locks on `secret_share_store` and network transmissions. [4](#0-3) 

**Attack Flow:**
1. Byzantine validator crafts well-formed `RequestShare` messages for a specific round
2. Sends them rapidly to victim validator (no BLS signature needed)
3. Messages pass through KLAST queue (10 capacity per peer) to verification
4. Verification is trivial and fast (just epoch check)
5. Messages accumulate in unbounded `verified_msg_rx` queue
6. Victim processes each request: locks store, retrieves share, serializes and sends response
7. Attacker receives responses but continues sending more requests
8. Unbounded queue grows indefinitely if requests arrive faster than processing
9. Memory exhaustion, CPU exhaustion from lock contention, network saturation

The channel configuration shows limited backpressure: [5](#0-4) 

With only 10 slots per peer in the input queue and an unbounded verification output queue, the protection is insufficient. [6](#0-5) 

## Impact Explanation

This is a **High Severity** vulnerability according to Aptos bug bounty criteria:

- **Validator Node Slowdowns**: Continuous lock contention on `secret_share_store` degrades performance
- **Resource Exhaustion**: Unbounded queue growth leads to memory exhaustion
- **Network Bandwidth Saturation**: Repeatedly sending the same share consumes bandwidth
- **Partial DoS**: Legitimate consensus messages may be delayed or dropped

The attack can be sustained indefinitely with minimal cost to the attacker (no expensive cryptographic operations required). Multiple Byzantine nodes could coordinate to amplify the attack across the validator set.

This breaks **Invariant #9 (Resource Limits)**: "All operations must respect gas, storage, and computational limits." The lack of rate limiting allows unlimited resource consumption.

While this doesn't directly break consensus safety, it can cause liveness issues by degrading validator performance or forcing node restarts.

## Likelihood Explanation

**Likelihood: High**

- **Easy to Exploit**: Attacker only needs to send well-formed `RequestShare` messages repeatedly
- **No Authentication Cost**: Unlike `Share` messages requiring BLS signatures, `RequestShare` has no cryptographic verification overhead
- **Low Attack Complexity**: Any Byzantine validator peer can execute this attack
- **Minimal Resources Required**: Attacker spends minimal CPU/bandwidth compared to victim
- **Persistent Attack**: Can be sustained indefinitely until victim node crashes or is restarted
- **Amplification Potential**: Multiple Byzantine nodes can coordinate to attack multiple validators simultaneously

The only barrier is network connectivity (must be a validator peer), which is a low threshold in a permissionless validator network.

## Recommendation

Implement multi-layered rate limiting and deduplication for `RequestShare` messages:

1. **Per-Peer Rate Limiting**: Track requests per peer per time window
2. **Request Deduplication**: Cache which peers have already received shares for each round
3. **Bounded Verified Queue**: Replace unbounded channel with bounded channel
4. **Request Signature Verification**: Require lightweight signature on RequestShare (optional, adds cost)

**Code Fix Example:**

```rust
struct ShareRequestTracker {
    // Track (peer, round) -> last_request_time
    requests: HashMap<(Author, Round), Instant>,
    rate_limit_window: Duration,
}

impl ShareRequestTracker {
    fn should_respond(&mut self, peer: Author, round: Round) -> bool {
        let key = (peer, round);
        let now = Instant::now();
        
        if let Some(last_time) = self.requests.get(&key) {
            if now.duration_since(*last_time) < self.rate_limit_window {
                return false; // Rate limited
            }
        }
        
        self.requests.insert(key, now);
        true
    }
}
```

Then in `handle_incoming_msg()`:

```rust
SecretShareMessage::RequestShare(request) => {
    if !self.request_tracker.lock().should_respond(
        peer_author, 
        request.metadata().round
    ) {
        // Drop rate-limited request
        return;
    }
    
    // Existing logic...
}
```

Additionally, replace the unbounded channel with a bounded one:

```rust
let (verified_msg_tx, mut verified_msg_rx) = 
    aptos_channel::new(QueueStyle::KLAST, 100, Some(&counters::VERIFIED_SECRET_SHARE_MSGS));
```

## Proof of Concept

```rust
// Test demonstrating the vulnerability
#[tokio::test]
async fn test_request_share_spam_attack() {
    use aptos_types::secret_sharing::SecretShareMetadata;
    use std::time::Duration;
    
    // Setup secret share manager and network
    let (network_sender, mut network_rx) = create_test_network();
    let manager = create_test_secret_share_manager(network_sender);
    
    // Byzantine attacker's address
    let attacker = AccountAddress::random();
    
    // Create RequestShare message
    let metadata = SecretShareMetadata {
        epoch: 1,
        round: 100,
        timestamp: 0,
        digest: vec![0u8; 32],
    };
    let request = SecretShareMessage::RequestShare(
        RequestSecretShare::new(metadata.clone())
    );
    
    // Simulate spam attack: send 1000 requests rapidly
    let mut response_count = 0;
    for _ in 0..1000 {
        // Send request
        manager.handle_incoming_msg(SecretShareRpc {
            msg: request.clone(),
            protocol: ProtocolId::ConsensusRpc,
            response_sender: oneshot::channel().0,
        });
        
        // Check if response was sent (in real attack, attacker receives these)
        if let Ok(Some(_response)) = network_rx.try_recv() {
            response_count += 1;
        }
        
        tokio::time::sleep(Duration::from_micros(100)).await;
    }
    
    // Vulnerability: All 1000 requests get responses
    // Expected with rate limiting: Far fewer responses
    println!("Responses sent: {}", response_count);
    assert!(response_count > 900, "No rate limiting detected");
}
```

**Expected Behavior**: Without rate limiting, the victim node processes all 1000 requests, repeatedly locking the store and sending responses.

**With Fix**: Rate limiting would reject most requests from the same peer for the same round, significantly reducing resource consumption.

## Notes

The vulnerability is exacerbated by the architectural choice to use an unbounded channel for verified messages combined with trivial verification for `RequestShare`. The KLAST queue at the network layer (10 capacity per peer) provides minimal protection since messages quickly move to the unbounded queue after verification.

This issue specifically affects the randomness beacon subsystem's secret sharing protocol. While it doesn't directly compromise consensus safety, it can degrade validator performance and potentially cause liveness issues during critical rounds where randomness is needed.

### Citations

**File:** consensus/src/rand/secret_sharing/secret_share_manager.rs (L286-308)
```rust
            SecretShareMessage::RequestShare(request) => {
                let result = self
                    .secret_share_store
                    .lock()
                    .get_self_share(request.metadata());
                match result {
                    Ok(Some(share)) => {
                        self.process_response(
                            protocol,
                            response_sender,
                            SecretShareMessage::Share(share),
                        );
                    },
                    Ok(None) => {
                        warn!(
                            "Self secret share could not be found for RPC request {}",
                            request.metadata().round
                        );
                    },
                    Err(e) => {
                        warn!("[SecretShareManager] Failed to get share: {}", e);
                    },
                }
```

**File:** consensus/src/rand/secret_sharing/secret_share_manager.rs (L333-333)
```rust
        let (verified_msg_tx, mut verified_msg_rx) = unbounded();
```

**File:** consensus/src/rand/secret_sharing/network_messages.rs (L28-38)
```rust
    pub fn verify(
        &self,
        epoch_state: &EpochState,
        config: &SecretShareConfig,
    ) -> anyhow::Result<()> {
        ensure!(self.epoch() == epoch_state.epoch);
        match self {
            SecretShareMessage::RequestShare(_) => Ok(()),
            SecretShareMessage::Share(share) => share.verify(config),
        }
    }
```

**File:** consensus/src/epoch_manager.rs (L1285-1290)
```rust
        let (secret_share_manager_tx, secret_share_manager_rx) =
            aptos_channel::new::<AccountAddress, IncomingSecretShareRequest>(
                QueueStyle::KLAST,
                self.config.internal_per_key_channel_size,
                None,
            );
```

**File:** config/src/config/consensus_config.rs (L242-242)
```rust
            internal_per_key_channel_size: 10,
```
