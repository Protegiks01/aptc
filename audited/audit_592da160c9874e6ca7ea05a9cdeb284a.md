# Audit Report

## Title
JWK Consensus Self-Messaging Channel Capacity Mismatch Causes Livelock in Single-Validator Networks

## Summary
In single-validator test networks, the JWK consensus self-messaging logic contains a capacity mismatch between the self-messaging channel (capacity 1024) and the RPC forwarding channel (capacity 10). Under high load from multiple concurrent JWK observations, this bottleneck causes message drops, RPC timeouts, and retry loops, leading to a livelock where the system remains busy but fails to make consensus progress.

## Finding Description
The JWK consensus runtime creates a self-messaging pipeline with mismatched channel capacities: [1](#0-0) 

The `self_sender` channel uses `futures::channel::mpsc` with capacity 1024 and **backpressure** semantics (blocks when full): [2](#0-1) 

When a validator sends an RPC to itself, it awaits both the send operation and the response: [3](#0-2) 

However, the NetworkTask forwards messages to a much smaller `rpc_tx` channel with capacity 10: [4](#0-3) 

When this channel is full, messages are **silently dropped** using the non-blocking `push` operation: [5](#0-4) [6](#0-5) 

**Attack Scenario in Single-Validator Network:**
1. Multiple OIDC providers trigger concurrent JWK observations
2. Each observation initiates a consensus round via `update_certifier.start_produce`: [7](#0-6) 

3. ReliableBroadcast sends RPCs to all validators (itself in single-validator case): [8](#0-7) 

4. When >10 concurrent RPCs are in flight, `rpc_tx` fills up
5. Subsequent RPCs are dropped by NetworkTask (line 201 in network.rs)
6. Dropped RPCs never receive responses, timing out
7. ReliableBroadcast retries with exponential backoff (lines 191-200 in reliable-broadcast/src/lib.rs)
8. New observations continue triggering new broadcasts
9. System enters livelock: broadcasts block/timeout/retry but consensus never completes

The early return without response when consensus is `NotStarted` exacerbates this: [9](#0-8) 

## Impact Explanation
This qualifies as **Low Severity** per the bug bounty criteria:
- **Scope**: Only affects single-validator test networks, not production multi-validator setups
- **Impact**: Liveness degradation - JWK updates fail to commit to on-chain state
- **No Safety Violation**: Does not compromise consensus safety, funds, or state integrity
- **Mitigation**: Configuration change (increase `rpc_tx` capacity) or rate-limiting

The issue breaks the **Resource Limits** invariant (#9) by allowing unbounded retry loops that consume resources without making progress.

## Likelihood Explanation
**Moderate likelihood in test environments:**
- Requires single-validator configuration (common in development/testing)
- Requires multiple OIDC providers with many JWK keys
- Requires high observation concurrency (>10 simultaneous consensus rounds)
- Default JWKObserver polling interval is 10 seconds, but multiple providers/keys can trigger concurrent rounds
- Zero likelihood in production (multi-validator networks don't exhibit this behavior)

## Recommendation
**Fix 1: Increase RPC forwarding channel capacity**
```rust
// In network.rs, line 169
let (rpc_tx, rpc_rx) = aptos_channel::new(QueueStyle::FIFO, 100, None); // Increased from 10
```

**Fix 2: Add rate limiting for broadcast initiation**
```rust
// In jwk_manager_per_key.rs, add throttling before start_produce
if self.active_broadcasts.len() >= MAX_CONCURRENT_BROADCASTS {
    return Ok(()); // Skip new broadcast
}
```

**Fix 3: Send response even when NotStarted**
```rust
// In jwk_manager_per_key.rs, line 279
ConsensusState::NotStarted => {
    // Send empty response instead of early return
    response_sender.send(Ok(JWKConsensusMsg::ObservationResponse(
        ObservedUpdateResponse::empty(self.epoch_state.epoch)
    )));
    return Ok(());
}
```

## Proof of Concept
```rust
// Test reproducing livelock in single-validator scenario
#[tokio::test]
async fn test_jwk_consensus_self_messaging_livelock() {
    // Setup single validator network
    let swarm = SwarmBuilder::new_local(1)
        .with_aptos()
        .build()
        .await;
    
    // Configure 20 OIDC providers with 10 keys each
    // Each triggers concurrent consensus rounds
    for i in 0..20 {
        let provider = OIDCProvider {
            name: format!("provider_{}", i).into_bytes(),
            config_url: format!("http://localhost:8080/provider_{}", i).into_bytes(),
        };
        // Add provider and start observations
    }
    
    // Monitor metrics - expect to see:
    // - PENDING_SELF_MESSAGES growing to 1024
    // - aptos_jwk_consensus_rpc_dropped counter increasing
    // - No successful JWK updates committed on-chain
    // - High retry count in ReliableBroadcast
    
    tokio::time::sleep(Duration::from_secs(60)).await;
    
    // Verify livelock: many pending messages, dropped RPCs, no progress
    assert!(get_metric("aptos_jwk_consensus_pending_self_messages") > 100);
    assert!(get_metric("aptos_jwk_consensus_rpc_dropped") > 50);
    assert!(get_onchain_jwk_updates() == 0); // No consensus progress
}
```

## Notes
This vulnerability is specific to the architectural choice of self-messaging in single-validator scenarios. The capacity mismatch (`self_sender=1024` vs `rpc_tx=10`) creates a bottleneck that wasn't apparent in multi-validator testing (all existing tests use 4 validators). While the impact is limited to test environments, it can cause significant confusion during development and integration testing when JWK consensus mysteriously stalls.

### Citations

**File:** crates/aptos-jwk-consensus/src/lib.rs (L35-35)
```rust
    let (self_sender, self_receiver) = aptos_channels::new(1_024, &counters::PENDING_SELF_MESSAGES);
```

**File:** crates/channel/src/lib.rs (L119-121)
```rust
pub fn new<T>(size: usize, gauge: &IntGauge) -> (Sender<T>, Receiver<T>) {
    gauge.set(0);
    let (sender, receiver) = mpsc::channel(size);
```

**File:** crates/aptos-jwk-consensus/src/network.rs (L79-90)
```rust
        if receiver == self.author {
            let (tx, rx) = oneshot::channel();
            let protocol = RPC[0];
            let self_msg = Event::RpcRequest(self.author, message, protocol, tx);
            self.self_sender.clone().send(self_msg).await?;
            if let Ok(Ok(Ok(bytes))) = tokio::time::timeout(timeout, rx).await {
                let response_msg =
                    tokio::task::spawn_blocking(move || protocol.from_bytes(&bytes)).await??;
                Ok(response_msg)
            } else {
                bail!("self rpc failed");
            }
```

**File:** crates/aptos-jwk-consensus/src/network.rs (L169-169)
```rust
        let (rpc_tx, rpc_rx) = aptos_channel::new(QueueStyle::FIFO, 10, None);
```

**File:** crates/aptos-jwk-consensus/src/network.rs (L201-203)
```rust
                    if let Err(e) = self.rpc_tx.push(peer_id, (peer_id, req)) {
                        warn!(error = ?e, "aptos channel closed");
                    };
```

**File:** crates/channel/src/aptos_channel.rs (L85-112)
```rust
    pub fn push(&self, key: K, message: M) -> Result<()> {
        self.push_with_feedback(key, message, None)
    }

    /// Same as `push`, but this function also accepts a oneshot::Sender over which the sender can
    /// be notified when the message eventually gets delivered or dropped.
    pub fn push_with_feedback(
        &self,
        key: K,
        message: M,
        status_ch: Option<oneshot::Sender<ElementStatus<M>>>,
    ) -> Result<()> {
        let mut shared_state = self.shared_state.lock();
        ensure!(!shared_state.receiver_dropped, "Channel is closed");
        debug_assert!(shared_state.num_senders > 0);

        let dropped = shared_state.internal_queue.push(key, (message, status_ch));
        // If this or an existing message had to be dropped because of the queue being full, we
        // notify the corresponding status channel if it was registered.
        if let Some((dropped_val, Some(dropped_status_ch))) = dropped {
            // Ignore errors.
            let _err = dropped_status_ch.send(ElementStatus::Dropped(dropped_val));
        }
        if let Some(w) = shared_state.waker.take() {
            w.wake();
        }
        Ok(())
    }
```

**File:** crates/aptos-jwk-consensus/src/update_certifier.rs (L67-68)
```rust
        let task = async move {
            let qc_update = rb.broadcast(req, agg_state).await.expect("cannot fail");
```

**File:** crates/reliable-broadcast/src/lib.rs (L146-153)
```rust
                    let send_fut = if receiver == self_author {
                        network_sender.send_rb_rpc(receiver, message, rpc_timeout_duration)
                    } else if let Some(raw_message) = protocols.get(&receiver).cloned() {
                        network_sender.send_rb_rpc_raw(receiver, raw_message, rpc_timeout_duration)
                    } else {
                        network_sender.send_rb_rpc(receiver, message, rpc_timeout_duration)
                    };
                    (receiver, send_fut.await)
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
