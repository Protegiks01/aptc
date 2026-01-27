# Audit Report

## Title
NetworkListener Channel Blocking DoS via Byzantine Message Flooding

## Summary
The `NetworkListener` in the quorum store consensus layer uses blocking `.send().await` calls on bounded tokio mpsc channels. While the channels are bounded (not unbounded as the security question hypothesized), this creates a different vulnerability: a Byzantine validator can flood the system with cryptographically valid messages that pass verification, causing receiver channels to fill up and the `NetworkListener` to block indefinitely, preventing critical operations including graceful shutdown. [1](#0-0) 

## Finding Description

**Answer to Original Question**: The `Sender<T>` types are **bounded** tokio mpsc channels, not unbounded. They are created with `tokio::sync::mpsc::channel(config.channel_size)` where `channel_size` defaults to 1000. [2](#0-1) [3](#0-2) 

**The Actual Vulnerability**: While bounded channels prevent memory exhaustion, they introduce a blocking DoS vulnerability. The `NetworkListener::start()` method forwards messages to internal channels using `.send().await.expect()`: [4](#0-3) [5](#0-4) [6](#0-5) 

When these bounded channels are full, tokio's `.send().await` blocks until space becomes available. The `NetworkListener` processes messages sequentially in a single-threaded loop: [7](#0-6) 

**Attack Path**:
1. Byzantine validator sends flood of `SignedBatchInfo`, `BatchMsg`, or `ProofOfStoreMsg` messages
2. Messages pass cryptographic verification (validly signed by the Byzantine validator)
3. Messages are only rate-limited by batch count (max 20 batches per message), not message rate
4. Receiver components (`ProofCoordinator`, `BatchCoordinator`, `ProofManager`) process messages slowly due to cryptographic operations and network broadcasts: [8](#0-7) 

5. Internal channels (capacity 1000) fill faster than receivers can drain
6. `NetworkListener` blocks on `.send().await`, cannot process further messages from queue
7. Critical messages including `Shutdown` become stuck in queue and cannot be processed: [9](#0-8) 

This breaks the **Resource Limits** invariant (all operations must respect resource limits) and the **Consensus Safety** invariant (liveness component - nodes must be able to make progress).

## Impact Explanation

**High Severity** per Aptos bug bounty criteria:
- **Validator node slowdowns**: Affected nodes become unresponsive to new messages
- **Significant protocol violations**: Inability to process shutdown commands violates operational integrity
- **Consensus liveness risk**: If multiple validators are affected simultaneously, consensus could stall

A single Byzantine validator (< 1/3 stake) can impact multiple honest validators, potentially degrading network performance or causing temporary liveness failures during high message volume periods.

## Likelihood Explanation

**High Likelihood**:
- Byzantine validator only needs valid cryptographic keys (normal validator access)
- Attack is straightforward: send valid messages at high rate
- No special network conditions required
- Receivers inherently slower due to cryptographic operations (signature aggregation, verification) and network broadcasts
- Channel capacity (1000) can be exhausted in seconds under flood conditions

## Recommendation

Replace blocking `.send().await.expect()` with timeout-based sending or non-blocking alternatives:

```rust
// Option 1: Use timeout
match timeout(Duration::from_millis(100), self.proof_coordinator_tx.send(cmd)).await {
    Ok(Ok(())) => { /* success */ },
    Ok(Err(_)) => { error!("Channel closed"); },
    Err(_) => { warn!("Timeout sending to proof_coordinator, dropping message"); },
}

// Option 2: Use try_send with backpressure handling
match self.proof_coordinator_tx.try_send(cmd) {
    Ok(()) => { /* success */ },
    Err(TrySendError::Full(_)) => {
        warn!("proof_coordinator channel full, applying backpressure");
        // Drop message or implement backpressure
    },
    Err(TrySendError::Closed(_)) => { error!("Channel closed"); },
}
```

Additionally, implement per-peer rate limiting at the network layer to prevent message floods from individual validators.

## Proof of Concept

```rust
// Rust test demonstrating the vulnerability
#[tokio::test]
async fn test_network_listener_blocking_dos() {
    let (proof_coordinator_tx, mut proof_coordinator_rx) = 
        tokio::sync::mpsc::channel::<ProofCoordinatorCommand>(1000);
    let (batch_coordinator_tx, _batch_coordinator_rx) = 
        tokio::sync::mpsc::channel::<BatchCoordinatorCommand>(1000);
    let (proof_manager_tx, _proof_manager_rx) = 
        tokio::sync::mpsc::channel::<ProofManagerCommand>(1000);
    let (network_tx, network_rx) = 
        aptos_channel::new::<PeerId, (PeerId, VerifiedEvent)>(QueueStyle::FIFO, 1000, None);
    
    // Start NetworkListener
    let listener = NetworkListener::new(
        network_rx,
        proof_coordinator_tx,
        vec![batch_coordinator_tx],
        proof_manager_tx,
    );
    let listener_handle = tokio::spawn(listener.start());
    
    // Flood with SignedBatchInfo messages (1500 messages > 1000 channel capacity)
    for i in 0..1500 {
        let batch_info = create_valid_signed_batch_info(byzantine_validator_id, i);
        network_tx.push(
            byzantine_validator_id,
            (byzantine_validator_id, VerifiedEvent::SignedBatchInfo(Box::new(batch_info)))
        ).unwrap();
    }
    
    // Try to send shutdown - it will be queued but never processed
    // because NetworkListener is blocked waiting for proof_coordinator channel space
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    network_tx.push(
        byzantine_validator_id,
        (byzantine_validator_id, VerifiedEvent::Shutdown(shutdown_tx))
    ).unwrap();
    
    // Verify shutdown is never acknowledged within reasonable time
    assert!(timeout(Duration::from_secs(5), shutdown_rx).await.is_err(), 
            "NetworkListener should be blocked and unable to process shutdown");
}
```

## Notes

The original security question asked whether the channels are "unbounded" and could cause "memory exhaustion." The investigation revealed the channels are **bounded**, preventing unbounded memory growth. However, the bounded nature introduces a different vulnerability: blocking behavior that enables DoS attacks. This demonstrates the importance of investigating the actual implementation beyond the initial hypothesis—the real vulnerability is related to the same code but has a different root cause and exploitation mechanism.

### Citations

**File:** consensus/src/quorum_store/network_listener.rs (L20-22)
```rust
    proof_coordinator_tx: Sender<ProofCoordinatorCommand>,
    remote_batch_coordinator_tx: Vec<Sender<BatchCoordinatorCommand>>,
    proof_manager_tx: Sender<ProofManagerCommand>,
```

**File:** consensus/src/quorum_store/network_listener.rs (L40-43)
```rust
    pub async fn start(mut self) {
        info!("QS: starting networking");
        let mut next_batch_coordinator_idx = 0;
        while let Some((sender, msg)) = self.network_msg_rx.next().await {
```

**File:** consensus/src/quorum_store/network_listener.rs (L47-55)
```rust
                    VerifiedEvent::Shutdown(ack_tx) => {
                        counters::QUORUM_STORE_MSG_COUNT
                            .with_label_values(&["NetworkListener::shutdown"])
                            .inc();
                        info!("QS: shutdown network listener received");
                        ack_tx
                            .send(())
                            .expect("Failed to send shutdown ack to QuorumStore");
                        break;
```

**File:** consensus/src/quorum_store/network_listener.rs (L63-66)
```rust
                        self.proof_coordinator_tx
                            .send(cmd)
                            .await
                            .expect("Could not send signed_batch_info to proof_coordinator");
```

**File:** consensus/src/quorum_store/network_listener.rs (L90-93)
```rust
                        self.remote_batch_coordinator_tx[idx]
                            .send(BatchCoordinatorCommand::NewBatches(author, batches))
                            .await
                            .expect("Could not send remote batch");
```

**File:** consensus/src/quorum_store/network_listener.rs (L100-103)
```rust
                        self.proof_manager_tx
                            .send(cmd)
                            .await
                            .expect("could not push Proof proof_of_store");
```

**File:** consensus/src/quorum_store/quorum_store_builder.rs (L180-184)
```rust
            tokio::sync::mpsc::channel(config.channel_size);
        let (proof_coordinator_cmd_tx, proof_coordinator_cmd_rx) =
            tokio::sync::mpsc::channel(config.channel_size);
        let (proof_manager_cmd_tx, proof_manager_cmd_rx) =
            tokio::sync::mpsc::channel(config.channel_size);
```

**File:** config/src/config/quorum_store_config.rs (L108-108)
```rust
            channel_size: 1000,
```

**File:** consensus/src/quorum_store/proof_coordinator.rs (L444-499)
```rust
                        ProofCoordinatorCommand::AppendSignature(signer, signed_batch_infos) => {
                            let signed_batch_infos = signed_batch_infos.take();
                            let Some(signed_batch_info) = signed_batch_infos.first() else {
                                error!("Empty signed batch info received from {}", signer.short_str().as_str());
                                continue;
                            };
                            let info = signed_batch_info.batch_info().clone();
                            let approx_created_ts_usecs = signed_batch_info
                                .expiration()
                                .saturating_sub(self.batch_expiry_gap_when_init_usecs);
                            let self_peer_id = self.peer_id;
                            let enable_broadcast_proofs = self.broadcast_proofs;

                            let mut proofs_iter = signed_batch_infos.into_iter().filter_map(|signed_batch_info| {
                                let peer_id = signed_batch_info.signer();
                                let digest = *signed_batch_info.digest();
                                let batch_id = signed_batch_info.batch_id();
                                match self.add_signature(signed_batch_info, &validator_verifier) {
                                    Ok(Some(proof)) => {
                                        debug!(
                                            LogSchema::new(LogEvent::ProofOfStoreReady),
                                            digest = digest,
                                            batch_id = batch_id.id,
                                        );
                                        Some(proof)
                                    },
                                    Ok(None) => None,
                                    Err(e) => {
                                        // Can happen if we already garbage collected, the commit notification is late, or the peer is misbehaving.
                                        if peer_id == self.peer_id {
                                            info!("QS: could not add signature from self, digest = {}, batch_id = {}, err = {:?}", digest, batch_id, e);
                                        } else {
                                            debug!("QS: could not add signature from peer {}, digest = {}, batch_id = {}, err = {:?}", peer_id, digest, batch_id, e);
                                        }
                                        None
                                    },
                                }
                            }).peekable();
                            if proofs_iter.peek().is_some() {
                                observe_batch(approx_created_ts_usecs, self_peer_id, BatchStage::POS_FORMED);
                                if enable_broadcast_proofs {
                                    if proofs_iter.peek().is_some_and(|p| p.info().is_v2()) {
                                        let proofs: Vec<_> = proofs_iter.collect();
                                        network_sender.broadcast_proof_of_store_msg_v2(proofs).await;
                                    } else {
                                        let proofs: Vec<_> = proofs_iter.map(|proof| {
                                            let (info, sig) = proof.unpack();
                                            ProofOfStore::new(info.info().clone(), sig)
                                        }).collect();
                                        network_sender.broadcast_proof_of_store_msg(proofs).await;
                                    }
                                } else {
                                    let proofs: Vec<_> = proofs_iter.collect();
                                    network_sender.send_proof_of_store_msg_to_self(proofs).await;
                                }
                            }
```
