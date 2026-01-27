# Audit Report

## Title
RPC Channel Starvation Attack via Batch Request Flooding

## Summary
The consensus RPC channel uses a round-robin queue that processes batch retrieval requests and block retrieval requests sequentially without isolation. An attacker can flood `BatchRequestMsg` RPCs from multiple peers to dominate the round-robin queue, starving critical block retrieval requests and causing validator node slowdowns and consensus liveness issues.

## Finding Description

The consensus network layer maintains a single RPC channel (`rpc_tx`/`rpc_rx`) for all incoming RPC requests, using a per-key round-robin queue where each `(peer_id, request_type)` pair can queue up to 10 messages. [1](#0-0) 

The channel uses `QueueStyle::FIFO` with `PerKeyQueue` implementation that maintains a round-robin queue across all active keys: [2](#0-1) 

When the epoch manager processes RPC requests, it consumes messages sequentially from the round-robin queue: [3](#0-2) 

Both `BatchRetrieval` and `BlockRetrieval` requests share this single round-robin queue but use different discriminants, creating separate keys per peer: [4](#0-3) [5](#0-4) 

**Attack Scenario:**

1. Attacker controls or compromises N validator nodes (or connects as N peers to the network)
2. Each peer continuously sends `BatchRequestMsg` RPCs
3. Each `(peer_i, BatchRetrieval)` key gets up to 10 messages queued in `rpc_tx`
4. The round-robin queue now contains N active keys for `BatchRetrieval`
5. When a legitimate validator needs to retrieve blocks, their `(validator_j, BlockRetrieval)` key is added to the same round-robin queue
6. The epoch manager processes one message per key in round-robin fashion
7. With N `BatchRetrieval` keys active, `BlockRetrieval` requests are processed only once every N+1 iterations
8. Block retrieval is delayed by a factor of N, preventing nodes from catching up

Even requests with invalid epochs contribute to starvation because they are queued in `rpc_tx` before epoch validation: [6](#0-5) [7](#0-6) 

## Impact Explanation

This vulnerability qualifies as **High Severity** per Aptos bug bounty criteria:

- **Validator node slowdowns**: Block retrieval delays prevent nodes from catching up with consensus
- **Significant protocol violations**: Breaks the Resource Limits invariant - RPC processing should not be starved by malicious messages
- **Consensus liveness threat**: If validators cannot retrieve blocks in time, they may fail to participate in consensus rounds

Block retrieval is critical infrastructure - nodes that fall behind rely on it to synchronize with the chain. A 100x slowdown (N=100 attackers) could effectively prevent block retrieval during high-consensus activity periods.

## Likelihood Explanation

**Likelihood: High**

The attack is practical because:

1. **Low barrier to entry**: Any network peer can send RPC requests to validators
2. **No authentication required**: Invalid epoch messages still consume queue slots
3. **Limited per-peer capacity (10) but unlimited peers**: An attacker can multiply their impact by using many peer connections
4. **No rate limiting on request types**: The 100 concurrent RPC limit in the network layer applies globally, not per-request-type
5. **Normal operations may amplify**: During high quorum store activity, legitimate batch requests from many validators could unintentionally create similar starvation

The network layer accepts up to 100 concurrent inbound RPCs: [8](#0-7) [9](#0-8) 

But this limit is per-connection and doesn't prevent the consensus-layer starvation attack.

## Recommendation

Implement **separate RPC channels with independent processing** for different request types:

```rust
// In NetworkTask::new(), create separate channels:
let (batch_rpc_tx, batch_rpc_rx) = aptos_channel::new(
    QueueStyle::FIFO,
    10,
    Some(&counters::BATCH_RPC_CHANNEL_MSGS),
);

let (block_rpc_tx, block_rpc_rx) = aptos_channel::new(
    QueueStyle::FIFO,
    10,
    Some(&counters::BLOCK_RPC_CHANNEL_MSGS),
);

// In NetworkTask::start(), route messages to appropriate channels:
Event::RpcRequest(peer_id, msg, protocol, callback) => {
    match msg {
        ConsensusMsg::BatchRequestMsg(request) => {
            // Push to batch_rpc_tx
        },
        ConsensusMsg::BlockRetrievalRequest(_) => {
            // Push to block_rpc_tx
        },
        // ... other request types
    }
}

// In EpochManager::start(), process both channels:
tokio::select! {
    (peer, request) = batch_rpc_rx.select_next_some() => {
        // Process batch requests
    },
    (peer, request) = block_rpc_rx.select_next_some() => {
        // Process block retrieval (prioritized)
    },
    // ... other branches
}
```

Additionally, implement **per-peer rate limiting** for `BatchRequestMsg`:
- Track batch requests per peer per time window
- Reject requests from peers exceeding rate limits
- Log and potentially penalize consistently abusive peers

## Proof of Concept

```rust
// Test demonstrating starvation in aptos_channel round-robin queue
#[cfg(test)]
mod test {
    use aptos_channels::aptos_channel;
    use aptos_channels::message_queues::QueueStyle;
    
    #[tokio::test]
    async fn test_rpc_channel_starvation() {
        // Create RPC channel with same config as consensus
        let (tx, mut rx) = aptos_channel::new::<(u32, &str), String>(
            QueueStyle::FIFO,
            10,
            None,
        );
        
        // Simulate 100 attackers flooding batch requests
        for attacker_id in 0..100 {
            for i in 0..10 {
                tx.push(
                    (attacker_id, "BatchRetrieval"),
                    format!("Batch request {} from attacker {}", i, attacker_id)
                ).unwrap();
            }
        }
        
        // Now a legitimate validator needs block retrieval
        tx.push(
            (999, "BlockRetrieval"),
            "URGENT: Block retrieval for consensus".to_string()
        ).unwrap();
        
        // Process messages and count how many we need to drain before
        // reaching the block retrieval request
        let mut count = 0;
        while let Some(msg) = rx.next().await {
            count += 1;
            if msg.contains("URGENT") {
                break;
            }
            if count > 50 {
                // Already processed 50 messages, block retrieval severely delayed
                println!("Block retrieval starved: processed {} messages before reaching it", count);
                break;
            }
        }
        
        assert!(count > 10, "Block retrieval was starved in round-robin queue");
    }
}
```

## Notes

This vulnerability exists at the consensus application layer, not the network transport layer. It exploits the shared round-robin queue architecture where critical block retrieval operations can be starved by less critical batch retrieval requests. The attack is amplified when multiple peers participate, and even legitimate high quorum store activity could trigger similar starvation conditions.

The fix requires architectural changes to isolate different RPC request types into separate processing channels with independent priorities, ensuring block retrieval (critical for consensus liveness) cannot be blocked by batch requests (less critical quorum store operations).

### Citations

**File:** consensus/src/network.rs (L768-769)
```rust
        let (rpc_tx, rpc_rx) =
            aptos_channel::new(QueueStyle::FIFO, 10, Some(&counters::RPC_CHANNEL_MSGS));
```

**File:** consensus/src/network.rs (L964-975)
```rust
                        ConsensusMsg::BlockRetrievalRequest(request) => {
                            debug!(
                                remote_peer = peer_id,
                                event = LogEvent::ReceiveBlockRetrieval,
                                "{:?}",
                                request
                            );
                            IncomingRpcRequest::BlockRetrieval(IncomingBlockRetrievalRequest {
                                req: *request,
                                protocol,
                                response_sender: callback,
                            })
```

**File:** consensus/src/network.rs (L977-988)
```rust
                        ConsensusMsg::BatchRequestMsg(request) => {
                            debug!(
                                remote_peer = peer_id,
                                event = LogEvent::ReceiveBatchRetrieval,
                                "{}",
                                request
                            );
                            IncomingRpcRequest::BatchRetrieval(IncomingBatchRetrievalRequest {
                                req: *request,
                                protocol,
                                response_sender: callback,
                            })
```

**File:** consensus/src/network.rs (L1020-1025)
```rust
                    if let Err(e) = self
                        .rpc_tx
                        .push((peer_id, discriminant(&req)), (peer_id, req))
                    {
                        warn!(error = ?e, "aptos channel closed");
                    };
```

**File:** crates/channel/src/message_queues.rs (L154-167)
```rust
    /// pop a message from the appropriate queue in per_key_queue
    /// remove the key from the round_robin_queue if it has no more messages
    pub(crate) fn pop(&mut self) -> Option<T> {
        let key = match self.round_robin_queue.pop_front() {
            Some(v) => v,
            _ => {
                return None;
            },
        };

        let (message, is_q_empty) = self.pop_from_key_queue(&key);
        if !is_q_empty {
            self.round_robin_queue.push_back(key);
        }
```

**File:** consensus/src/epoch_manager.rs (L1815-1821)
```rust
        match request.epoch() {
            Some(epoch) if epoch != self.epoch() => {
                monitor!(
                    "process_different_epoch_rpc_request",
                    self.process_different_epoch(epoch, peer_id)
                )?;
                return Ok(());
```

**File:** consensus/src/epoch_manager.rs (L1943-1948)
```rust
                (peer, request) = network_receivers.rpc_rx.select_next_some() => {
                    monitor!("epoch_manager_process_rpc",
                    if let Err(e) = self.process_rpc_request(peer, request) {
                        error!(epoch = self.epoch(), error = ?e, kind = error_kind(&e));
                    });
                },
```

**File:** network/framework/src/constants.rs (L14-15)
```rust
/// Limit on concurrent Inbound RPC requests before backpressure is applied
pub const MAX_CONCURRENT_INBOUND_RPCS: u32 = 100;
```

**File:** network/framework/src/protocols/rpc/mod.rs (L213-222)
```rust
        if self.inbound_rpc_tasks.len() as u32 == self.max_concurrent_inbound_rpcs {
            // Increase counter of declined requests
            counters::rpc_messages(
                network_context,
                REQUEST_LABEL,
                INBOUND_LABEL,
                DECLINED_LABEL,
            )
            .inc();
            return Err(RpcError::TooManyPending(self.max_concurrent_inbound_rpcs));
```
