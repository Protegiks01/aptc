# Audit Report

## Title
Resource Exhaustion via Unbounded Vector Deserialization in RandMessage

## Summary
Byzantine validators can send `RandMessage::AugData` messages with arbitrarily large `Delta.rks` vectors (up to ~1.3 million G1Projective points within the 64 MiB network limit). The consensus layer deserializes these vectors before validating their length, causing excessive CPU and memory consumption that degrades validator performance.

## Finding Description

The randomness generation protocol uses `RandMessage` to exchange augmented data between validators. The `AugmentedData` structure contains a `Delta` (alias for `RandomizedPKs`) which has an unbounded vector of elliptic curve points: [1](#0-0) 

Each validator is expected to send a `Delta` where `rks.len()` equals their legitimate public key share count (typically small, matching the number of validator shares). However, a Byzantine validator can craft a malicious `AugData` message with thousands or millions of points in the `rks` vector.

**Attack Flow:**

1. **Message Creation**: Byzantine validator creates `AugmentedData` with `delta.rks` containing 1+ million G1Projective points (each ~48 bytes), fitting within the 64 MiB network limit.

2. **Network Transmission**: The message passes through the network layer's size checks (MAX_MESSAGE_SIZE = 64 MiB). [2](#0-1) 

3. **Deserialization Without Length Validation**: In the verification task, the message is deserialized using standard BCS without vector length limits (only recursion depth is limited): [3](#0-2) 

BCS deserialization allocates memory for the entire vector and parses each G1Projective point **before any validation occurs**.

4. **Late Validation Failure**: Only after successful deserialization does the verify function execute, which calls `derive_apk`: [4](#0-3) [5](#0-4) 

5. **Length Check After Resource Consumption**: The validation finally checks `delta.rks.len() == pk.len()` and rejects the message: [6](#0-5) 

However, the resource damage (CPU for parsing millions of elliptic curve points, memory allocation for large vectors) has already occurred.

**The vulnerability violates the "Resource Limits" invariant**: The system should validate message size constraints before performing expensive operations, but instead performs full deserialization before any semantic validation.

## Impact Explanation

This qualifies as **High Severity** under the Aptos Bug Bounty program criteria: "Validator node slowdowns."

A coordinated attack by Byzantine validators can:
- Send repeated oversized `RandMessage::AugData` messages to all honest validators
- Each message triggers ~1.3 million G1Projective point deserializations (48 MB * 1.3M = up to 62 MiB of parsing)
- CPU exhaustion from elliptic curve point parsing
- Memory pressure from large vector allocations
- Degraded consensus performance as validators spend resources processing invalid messages

While not causing permanent liveness loss (requires Critical severity), this creates significant operational disruption requiring validator operators to implement rate limiting or firewall rules.

## Likelihood Explanation

**High likelihood** of exploitation:
- Any Byzantine validator can execute this attack (requires no special privileges beyond validator status)
- Attack is simple: serialize a valid `AugmentedData` structure with an oversized `rks` vector
- No cryptographic breaking required
- Can be automated and repeated continuously
- Detection is difficult as messages appear structurally valid until verification

The only barrier is that the attacker must be a validator to send consensus messages, but this is the standard threat model for Byzantine consensus protocols.

## Recommendation

Implement vector length validation **before** deserialization in the verification task. Add a maximum expected size check on the raw message bytes:

```rust
async fn verification_task(
    epoch_state: Arc<EpochState>,
    mut incoming_rpc_request: aptos_channel::Receiver<Author, IncomingRandGenRequest>,
    verified_msg_tx: UnboundedSender<RpcRequest<S, D>>,
    rand_config: RandConfig,
    fast_rand_config: Option<RandConfig>,
    bounded_executor: BoundedExecutor,
) {
    // Define maximum reasonable size for RandMessage
    // Each validator has ~100-200 shares typically, Delta has 2 vectors
    // 500 shares * 48 bytes * 2 vectors * 2 (regular + fast path) = ~200KB
    const MAX_RAND_MESSAGE_SIZE: usize = 1_000_000; // 1MB safety margin
    
    while let Some(rand_gen_msg) = incoming_rpc_request.next().await {
        let tx = verified_msg_tx.clone();
        let epoch_state_clone = epoch_state.clone();
        let config_clone = rand_config.clone();
        let fast_config_clone = fast_rand_config.clone();
        bounded_executor
            .spawn(async move {
                // Check size before deserialization
                if rand_gen_msg.req.data().len() > MAX_RAND_MESSAGE_SIZE {
                    warn!("RandMessage size {} exceeds maximum {}", 
                          rand_gen_msg.req.data().len(), MAX_RAND_MESSAGE_SIZE);
                    return;
                }
                
                match bcs::from_bytes::<RandMessage<S, D>>(rand_gen_msg.req.data()) {
                    // ... rest unchanged
```

Alternatively, implement a custom deserializer that validates vector lengths against expected validator set size before allocating memory.

## Proof of Concept

```rust
#[test]
fn test_oversized_delta_dos() {
    use aptos_crypto::blstrs::G1Projective;
    use group::Group;
    
    // Create a malicious Delta with excessive points
    let mut rks = Vec::new();
    for _ in 0..100_000 {  // 100K points = ~4.8MB
        rks.push(G1Projective::generator());
    }
    
    let malicious_delta = RandomizedPKs {
        pi: G1Projective::generator(),
        rks,
    };
    
    let malicious_aug_data = AugmentedData {
        delta: malicious_delta.clone(),
        fast_delta: Some(malicious_delta),
    };
    
    let aug_data_msg = AugData::new(1, Author::random(), malicious_aug_data);
    let rand_msg = RandMessage::AugData(aug_data_msg);
    
    // Serialize - this will succeed and fit in network limits
    let serialized = bcs::to_bytes(&rand_msg).unwrap();
    println!("Malicious message size: {} bytes", serialized.len());
    
    // Measure deserialization time
    let start = std::time::Instant::now();
    let deserialized = bcs::from_bytes::<RandMessage<Share, AugmentedData>>(&serialized);
    let duration = start.elapsed();
    
    println!("Deserialization took: {:?}", duration);
    // Deserialization succeeds, consuming resources
    assert!(deserialized.is_ok());
    
    // Verification will fail, but damage is done
    let config = create_test_rand_config();
    let result = deserialized.unwrap().verify(&epoch_state, &config, &None, sender);
    assert!(result.is_err());  // Fails at validation stage
}
```

## Notes

The vulnerability exists because BCS deserialization only enforces recursion depth limits (RECURSION_LIMIT = 64), not vector length or total allocation size limits. The network layer's MAX_MESSAGE_SIZE provides an upper bound, but allows ~1.3 million G1Projective points to be packed into a single message, causing significant resource consumption during deserialization before the semantic validation rejects the malformed message.

### Citations

**File:** crates/aptos-dkg/src/weighted_vuf/pinkas/mod.rs (L38-42)
```rust
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RandomizedPKs {
    pi: G1Projective,       // \hat{g}^{r}
    rks: Vec<G1Projective>, // g^{r \sk_i}, for all shares i
}
```

**File:** crates/aptos-dkg/src/weighted_vuf/pinkas/mod.rs (L114-120)
```rust
        if delta.rks.len() != pk.len() {
            bail!(
                "Expected PKs and RKs to be of the same length. Got {} and {}, respectively.",
                delta.rks.len(),
                pk.len()
            );
        }
```

**File:** config/src/config/network_config.rs (L45-50)
```rust
pub const MAX_MESSAGE_METADATA_SIZE: usize = 128 * 1024; /* 128 KiB: a buffer for metadata that might be added to messages by networking */
pub const MESSAGE_PADDING_SIZE: usize = 2 * 1024 * 1024; /* 2 MiB: a safety buffer to allow messages to get larger during serialization */
pub const MAX_APPLICATION_MESSAGE_SIZE: usize =
    (MAX_MESSAGE_SIZE - MAX_MESSAGE_METADATA_SIZE) - MESSAGE_PADDING_SIZE; /* The message size that applications should check against */
pub const MAX_FRAME_SIZE: usize = 4 * 1024 * 1024; /* 4 MiB large messages will be chunked into multiple frames and streamed */
pub const MAX_MESSAGE_SIZE: usize = 64 * 1024 * 1024; /* 64 MiB */
```

**File:** consensus/src/rand/rand_gen/rand_manager.rs (L236-257)
```rust
                    match bcs::from_bytes::<RandMessage<S, D>>(rand_gen_msg.req.data()) {
                        Ok(msg) => {
                            if msg
                                .verify(
                                    &epoch_state_clone,
                                    &config_clone,
                                    &fast_config_clone,
                                    rand_gen_msg.sender,
                                )
                                .is_ok()
                            {
                                let _ = tx.unbounded_send(RpcRequest {
                                    req: msg,
                                    protocol: rand_gen_msg.protocol,
                                    response_sender: rand_gen_msg.response_sender,
                                });
                            }
                        },
                        Err(e) => {
                            warn!("Invalid rand gen message: {}", e);
                        },
                    }
```

**File:** consensus/src/rand/rand_gen/types.rs (L196-215)
```rust
    fn verify(
        &self,
        rand_config: &RandConfig,
        fast_rand_config: &Option<RandConfig>,
        author: &Author,
    ) -> anyhow::Result<()> {
        rand_config
            .derive_apk(author, self.delta.clone())
            .map(|_| ())?;

        ensure!(
            self.fast_delta.is_some() == fast_rand_config.is_some(),
            "Fast path delta should be present iff fast_rand_config is present."
        );
        if let (Some(config), Some(fast_delta)) = (fast_rand_config, self.fast_delta.as_ref()) {
            config.derive_apk(author, fast_delta.clone()).map(|_| ())
        } else {
            Ok(())
        }
    }
```

**File:** consensus/src/rand/rand_gen/types.rs (L656-659)
```rust
    fn derive_apk(&self, peer: &Author, delta: Delta) -> anyhow::Result<APK> {
        let apk = WVUF::augment_pubkey(&self.vuf_pp, self.get_pk_share(peer).clone(), delta)?;
        Ok(apk)
    }
```
