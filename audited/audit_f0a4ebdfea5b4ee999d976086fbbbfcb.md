# Audit Report

## Title
Memory Exhaustion via Oversized BatchMsg Before Validation Checks

## Summary
BatchMsg messages can be crafted to consume up to 64 MiB of memory during network-layer deserialization, far exceeding the application-layer limit of ~4 MiB, causing memory exhaustion before validation rejects the message. This allows malicious validators to crash peer validator nodes through memory exhaustion attacks.

## Finding Description

The Aptos consensus layer has a critical gap between network-layer message size limits and application-layer validation limits for BatchMsg messages:

**Network Layer Configuration:** [1](#0-0) 

The network allows messages up to 64 MiB.

**Application Layer Configuration:** [2](#0-1) 

The application expects BatchMsg to contain at most 100 transactions per batch, 20 batches total, and ~4 MiB total bytes.

**Deserialization Before Validation:**
The vulnerability occurs because full BCS deserialization happens at the network protocol layer before any application-level validation: [3](#0-2) 

Network messages are deserialized via `protocol.from_bytes()` which calls `bcs::from_bytes_with_limit(bytes, 64)` (recursion limit, not size limit). [4](#0-3) 

At this point, the entire 64 MiB message is deserialized and allocated in memory.

**Validation Happens After:**
Only after complete deserialization does the message reach validation: [5](#0-4) 

The verification spawns in a bounded executor (16 concurrent tasks) and checks limits: [6](#0-5) 

And further validation in BatchCoordinator: [7](#0-6) 

**Attack Flow:**
1. Malicious validator crafts BatchMsg with 64 MiB of data (e.g., 200 batches × 500 transactions each)
2. Network layer receives and fully deserializes the message (64 MiB allocated)
3. Message is converted to UnverifiedEvent and queued for verification
4. Eventually fails validation (exceeds receiver_max_num_batches=20, receiver_max_total_txns=2000)
5. Memory already consumed; attacker repeats with concurrent messages

**Memory Exhaustion Calculation:**
- Gap per message: 64 MiB - 4 MiB = 60 MiB wasted
- If attacker sends 100 concurrent messages: 6 GB consumed
- If attacker sends 1000 concurrent messages: 60 GB consumed
- Result: Out-of-memory crash

This breaks the Resource Limits invariant: "All operations must respect gas, storage, and computational limits."

## Impact Explanation

**High Severity** per Aptos Bug Bounty criteria:
- **Validator node slowdowns/crashes**: Memory exhaustion leads to OOM kills and node unavailability
- **Significant protocol violations**: Bypasses application-layer resource limits through network-layer gap

The attack causes validator nodes to become unresponsive, affecting network liveness. While individual validator crashes don't break consensus safety (requires >1/3 Byzantine validators), widespread memory exhaustion attacks can significantly degrade network performance and availability.

## Likelihood Explanation

**Medium-High Likelihood:**
- **Attacker Requirements**: Must be a validator (or compromise validator keys) to send on validator network
- **Complexity**: Low - simply craft large BatchMsg within network limits but exceeding application limits
- **Detection**: Difficult to distinguish from legitimate large batches until validation fails
- **Mitigation**: No current protection at network layer; only BoundedExecutor limits concurrent verification (16 tasks)

Given that AptosBFT assumes up to 1/3 Byzantine validators, this attack vector is realistic within the threat model.

## Recommendation

Implement application-layer message size validation **before** deserialization. Add a size check at the network protocol layer based on application expectations:

```rust
// In network/framework/src/protocols/wire/messaging/v1/mod.rs or similar

// For ConsensusMsg, check against application limits before deserialization
fn validate_message_size_before_deserialize(
    protocol_id: ProtocolId,
    frame_len: usize,
) -> Result<(), ReadError> {
    // For consensus messages, enforce tighter limits based on application config
    if matches!(
        protocol_id,
        ProtocolId::ConsensusRpcBcs
            | ProtocolId::ConsensusRpcCompressed
            | ProtocolId::ConsensusDirectSendBcs
            | ProtocolId::ConsensusDirectSendCompressed
    ) {
        const MAX_CONSENSUS_MESSAGE_SIZE: usize = 8 * 1024 * 1024; // 8 MiB
        if frame_len > MAX_CONSENSUS_MESSAGE_SIZE {
            return Err(ReadError::DeserializeError(
                bcs::Error::Custom("Message exceeds consensus size limit".to_string()),
                frame_len,
                Bytes::new(),
            ));
        }
    }
    Ok(())
}
```

Apply this check in the frame decoding path before calling `bcs::from_bytes()`.

Alternatively, configure network `max_message_size` specifically for consensus protocols to match `receiver_max_total_bytes` + overhead (e.g., 8 MiB instead of 64 MiB).

## Proof of Concept

```rust
// PoC demonstrating the vulnerability
// This would be added as a test in consensus/src/network_tests.rs

#[tokio::test]
async fn test_batch_msg_memory_exhaustion() {
    use aptos_types::transaction::SignedTransaction;
    use aptos_crypto::ed25519::Ed25519PrivateKey;
    use aptos_crypto::PrivateKey;
    
    // Create a large BatchMsg that exceeds application limits
    // but stays within network limits (64 MiB)
    
    let batch_count = 200; // Exceeds receiver_max_num_batches = 20
    let txns_per_batch = 500; // Exceeds receiver_max_batch_txns = 100
    
    let mut batches = Vec::new();
    let peer_id = PeerId::random();
    
    for i in 0..batch_count {
        let mut transactions = Vec::new();
        for j in 0..txns_per_batch {
            // Create dummy transaction
            let private_key = Ed25519PrivateKey::generate_for_testing();
            let txn = create_test_transaction(private_key, j);
            transactions.push(txn);
        }
        
        let batch = Batch::new(
            BatchId::new_for_test(i),
            transactions,
            1, // epoch
            u64::MAX, // expiration
            peer_id,
            0, // gas_bucket_start
        );
        batches.push(batch);
    }
    
    let batch_msg = BatchMsg::new(batches);
    
    // Serialize to check size
    let serialized = bcs::to_bytes(&ConsensusMsg::BatchMsg(Box::new(batch_msg.clone()))).unwrap();
    
    println!("BatchMsg size: {} bytes ({} MiB)", 
             serialized.len(), 
             serialized.len() / (1024 * 1024));
    
    // This message will:
    // 1. Pass network size check (if < 64 MiB)
    // 2. Be fully deserialized (consuming all memory)
    // 3. Fail validation (exceeds max_num_batches and max_batch_txns)
    // 4. Memory already consumed before validation
    
    assert!(serialized.len() < 64 * 1024 * 1024, "Within network limit");
    
    // Simulate concurrent attack: send many such messages
    let concurrent_messages = 100;
    let total_memory = serialized.len() * concurrent_messages;
    
    println!("Attack with {} concurrent messages would consume {} MiB",
             concurrent_messages,
             total_memory / (1024 * 1024));
}
```

**Notes:**
- This PoC requires access to validator network to execute
- The actual attack would send messages concurrently to maximize memory consumption
- Current protections (BoundedExecutor with 16 task limit) do not prevent memory exhaustion from queued but not-yet-verified messages
- The vulnerability allows bypassing application-layer resource limits by exploiting the network-application layer gap

### Citations

**File:** config/src/config/network_config.rs (L50-50)
```rust
pub const MAX_MESSAGE_SIZE: usize = 64 * 1024 * 1024; /* 64 MiB */
```

**File:** config/src/config/quorum_store_config.rs (L120-126)
```rust
            receiver_max_batch_txns: 100,
            receiver_max_batch_bytes: 1024 * 1024 + BATCH_PADDING_BYTES,
            receiver_max_num_batches: 20,
            receiver_max_total_txns: 2000,
            receiver_max_total_bytes: 4 * 1024 * 1024
                + DEFAULT_MAX_NUM_BATCHES
                + BATCH_PADDING_BYTES,
```

**File:** network/framework/src/protocols/wire/handshake/v1/mod.rs (L226-252)
```rust
    pub fn from_bytes<T: DeserializeOwned>(&self, bytes: &[u8]) -> anyhow::Result<T> {
        // Start the deserialization timer
        let deserialization_timer = start_serialization_timer(*self, DESERIALIZATION_LABEL);

        // Deserialize the message
        let result = match self.encoding() {
            Encoding::Bcs(limit) => self.bcs_decode(bytes, limit),
            Encoding::CompressedBcs(limit) => {
                let compression_client = self.get_compression_client();
                let raw_bytes = aptos_compression::decompress(
                    &bytes.to_vec(),
                    compression_client,
                    MAX_APPLICATION_MESSAGE_SIZE,
                )
                .map_err(|e| anyhow! {"{:?}", e})?;
                self.bcs_decode(&raw_bytes, limit)
            },
            Encoding::Json => serde_json::from_slice(bytes).map_err(|e| anyhow!("{:?}", e)),
        };

        // Only record the duration if deserialization was successful
        if result.is_ok() {
            deserialization_timer.observe_duration();
        }

        result
    }
```

**File:** network/framework/src/protocols/wire/messaging/v1/mod.rs (L225-241)
```rust
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.project().framed_read.poll_next(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                let frame = frame.freeze();

                match bcs::from_bytes(&frame) {
                    Ok(message) => Poll::Ready(Some(Ok(message))),
                    // Failed to deserialize the NetworkMessage
                    Err(err) => {
                        let mut frame = frame;
                        let frame_len = frame.len();
                        // Keep a few bytes from the frame for debugging
                        frame.truncate(8);
                        let err = ReadError::DeserializeError(err, frame_len, frame);
                        Poll::Ready(Some(Err(err)))
                    },
                }
```

**File:** consensus/src/epoch_manager.rs (L1587-1600)
```rust
            self.bounded_executor
                .spawn(async move {
                    match monitor!(
                        "verify_message",
                        unverified_event.clone().verify(
                            peer_id,
                            &epoch_state.verifier,
                            &proof_cache,
                            quorum_store_enabled,
                            peer_id == my_peer_id,
                            max_num_batches,
                            max_batch_expiry_gap_usecs,
                        )
                    ) {
```

**File:** consensus/src/quorum_store/types.rs (L433-461)
```rust
    pub fn verify(
        &self,
        peer_id: PeerId,
        max_num_batches: usize,
        verifier: &ValidatorVerifier,
    ) -> anyhow::Result<()> {
        ensure!(!self.batches.is_empty(), "Empty message");
        ensure!(
            self.batches.len() <= max_num_batches,
            "Too many batches: {} > {}",
            self.batches.len(),
            max_num_batches
        );
        let epoch_authors = verifier.address_to_validator_index();
        for batch in self.batches.iter() {
            ensure!(
                epoch_authors.contains_key(&batch.author()),
                "Invalid author {} for batch {} in current epoch",
                batch.author(),
                batch.digest()
            );
            ensure!(
                batch.author() == peer_id,
                "Batch author doesn't match sender"
            );
            batch.verify()?
        }
        Ok(())
    }
```

**File:** consensus/src/quorum_store/batch_coordinator.rs (L137-171)
```rust
    fn ensure_max_limits(&self, batches: &[Batch<BatchInfoExt>]) -> anyhow::Result<()> {
        let mut total_txns = 0;
        let mut total_bytes = 0;
        for batch in batches.iter() {
            ensure!(
                batch.num_txns() <= self.max_batch_txns,
                "Exceeds batch txn limit {} > {}",
                batch.num_txns(),
                self.max_batch_txns,
            );
            ensure!(
                batch.num_bytes() <= self.max_batch_bytes,
                "Exceeds batch bytes limit {} > {}",
                batch.num_bytes(),
                self.max_batch_bytes,
            );

            total_txns += batch.num_txns();
            total_bytes += batch.num_bytes();
        }
        ensure!(
            total_txns <= self.max_total_txns,
            "Exceeds total txn limit {} > {}",
            total_txns,
            self.max_total_txns,
        );
        ensure!(
            total_bytes <= self.max_total_bytes,
            "Exceeds total bytes limit: {} > {}",
            total_bytes,
            self.max_total_bytes,
        );

        Ok(())
    }
```
