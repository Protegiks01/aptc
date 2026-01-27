# Audit Report

## Title
Mempool Broadcast DoS via ACK Withholding Attack

## Summary
An attacker can permanently block mempool transaction broadcasts to their peer by never sending ACK responses. The `determine_broadcast_batch()` function enforces a limit on pending (un-ACKed) broadcasts per peer, and when this limit is reached, all new broadcasts are blocked indefinitely, creating a repeating cycle of rebroadcasting expired messages while blocking fresh transaction propagation.

## Finding Description

The vulnerability exists in the mempool broadcast mechanism that propagates transactions across the Aptos network. The core issue lies in how `determine_broadcast_batch()` handles pending broadcasts and enforces the `max_broadcasts_per_peer` limit. [1](#0-0) 

The function counts non-expired un-ACKed broadcasts as `pending_broadcasts` and blocks all new broadcasts when this count reaches `max_broadcasts_per_peer`. The configuration sets this limit to **2 for validators** and **20 for fullnodes**: [2](#0-1) [3](#0-2) 

When a broadcast message expires (after `shared_mempool_ack_timeout_ms`, default 2 seconds), it becomes eligible for rebroadcast. However, the rebroadcast updates the message's timestamp in `sent_messages`, resetting the expiration timer: [4](#0-3) 

**Attack Flow:**

1. Malicious peer connects to an honest node and never sends `BroadcastTransactionsResponse` (ACK) messages
2. Honest node sends broadcasts #1 and #2 to attacker (for validators with `max_broadcasts_per_peer=2`)
3. Both broadcasts remain in `sent_messages` without ACKs, counting as pending
4. Node attempts broadcast #3 → blocked by `TooManyPendingBroadcasts` error (2 ≥ 2)
5. After 2 seconds, broadcast #1 expires and gets rebroadcast, timestamp updated
6. Shortly after, broadcast #2 expires and gets rebroadcast, timestamp updated  
7. Any new broadcast attempts during the non-expired windows (majority of time) are blocked
8. Cycle repeats indefinitely: rebroadcast expired → block new for ~2s → rebroadcast next expired → block new

The broadcast messages are stored in a `BTreeMap` that only gets cleaned when transactions are committed: [5](#0-4) 

However, as new transactions continuously arrive in the mempool, new broadcasts are created for these uncommitted transactions, and the attacker can maintain the maximum pending broadcasts indefinitely by never ACKing.

The ACK processing logic shows that ACKs are meant to remove messages from `sent_messages`: [6](#0-5) 

## Impact Explanation

This is a **High Severity** vulnerability per the Aptos bug bounty program criteria:

**"Validator node slowdowns, Significant protocol violations"**

**Specific Impacts:**

1. **Transaction Propagation Degradation**: Prevents the victim node from broadcasting new transactions to the attacker's peer, degrading overall network transaction propagation speed

2. **Validator Impact** (when quorum store disabled): With `max_broadcasts_per_peer=2`, a malicious validator can block all broadcasts from honest validators after just 2 un-ACKed messages, severely limiting mempool synchronization

3. **Fullnode Impact**: Malicious VFNs or PFNs can block broadcasts from honest nodes with just 20 un-ACKed messages, affecting downstream transaction propagation

4. **Censorship Potential**: Attacker can selectively prevent specific transactions from being broadcast to them, enabling targeted censorship attacks

5. **Network-Wide Effect**: Multiple attackers connecting to different honest nodes can collectively degrade transaction propagation across the entire network

The attack does NOT break consensus safety or cause fund loss, preventing it from being Critical severity. However, it significantly degrades network liveness and protocol correctness.

## Likelihood Explanation

**Likelihood: High**

**Attacker Requirements:**
- Establish a P2P connection to the victim node (trivial for public networks)
- Simply not send ACK responses (requires no special access or resources)
- No need for validator privileges or stake

**Attack Complexity:**
- Extremely low - attacker just ignores incoming broadcast requests
- No sophisticated exploit code needed
- Can be executed by modifying a standard node to drop ACKs

**Detection Difficulty:**
- Hard to distinguish from a legitimately slow or unresponsive peer
- No clear signal that peer is malicious vs. having network issues
- Existing monitoring doesn't specifically track un-ACKed broadcasts per peer

**Scope:**
- Affects all node types: validators, VFNs, PFNs
- Works on all networks: validator network, VFN network, public network
- Sustainable indefinitely as long as attacker stays connected

## Recommendation

Implement a maximum lifetime for un-ACKed broadcasts and disconnect peers that consistently fail to ACK. Add the following mitigations:

```rust
// In BroadcastInfo, track first send time for each message
pub struct BroadcastInfo {
    pub sent_messages: BTreeMap<MempoolMessageId, SystemTime>,
    pub first_sent_time: BTreeMap<MempoolMessageId, SystemTime>, // NEW
    pub retry_messages: BTreeSet<MempoolMessageId>,
    pub backoff_mode: bool,
}

// In determine_broadcast_batch(), add maximum rebroadcast limit
const MAX_BROADCAST_LIFETIME_MS: u64 = 30_000; // 30 seconds
const MAX_REBROADCAST_ATTEMPTS: usize = 5;

// When checking expired messages, also check total lifetime
for (message, sent_time) in state.broadcast_info.sent_messages.iter() {
    let first_sent = state.broadcast_info.first_sent_time.get(message)
        .unwrap_or(sent_time);
    
    let lifetime = SystemTime::now()
        .duration_since(*first_sent)
        .unwrap_or(Duration::ZERO);
    
    // If message has been pending too long, remove it and penalize peer
    if lifetime.as_millis() > MAX_BROADCAST_LIFETIME_MS {
        state.broadcast_info.sent_messages.remove(message);
        state.broadcast_info.first_sent_time.remove(message);
        // Log peer health issue - could trigger disconnection
        warn!("Peer {} has un-ACKed broadcast for {}ms", peer, lifetime.as_millis());
        continue;
    }
    
    // Existing expiration logic...
}
```

**Additional Mitigations:**
1. Track ACK rate per peer and disconnect peers with consistently low ACK rates
2. Implement peer reputation system that prioritizes responsive peers
3. Add metrics for monitoring un-ACKed broadcast counts per peer
4. Consider making `max_broadcasts_per_peer` adaptive based on network conditions

## Proof of Concept

```rust
#[cfg(test)]
mod test {
    use super::*;
    use aptos_config::config::MempoolConfig;
    use std::time::{Duration, SystemTime};

    #[test]
    fn test_ack_withholding_dos() {
        // Setup: Create mempool network interface with validator config
        let mut config = MempoolConfig::default();
        config.max_broadcasts_per_peer = 2; // Validator setting
        config.shared_mempool_ack_timeout_ms = 2000; // 2 second timeout
        
        // Simulate mempool with transactions
        let mempool = create_test_mempool_with_txns(100); // 100 test transactions
        let peer = create_test_peer();
        
        // Attack: Send broadcasts without ACKing
        
        // Broadcast #1 - should succeed
        let result1 = network_interface.execute_broadcast(peer, false, &mut smp).await;
        assert!(result1.is_ok(), "First broadcast should succeed");
        
        // Broadcast #2 - should succeed  
        let result2 = network_interface.execute_broadcast(peer, false, &mut smp).await;
        assert!(result2.is_ok(), "Second broadcast should succeed");
        
        // Broadcast #3 - should FAIL with TooManyPendingBroadcasts
        let result3 = network_interface.execute_broadcast(peer, false, &mut smp).await;
        assert!(matches!(result3, Err(BroadcastError::TooManyPendingBroadcasts(_))),
            "Third broadcast should fail with TooManyPendingBroadcasts");
        
        // Wait for first message to expire
        tokio::time::sleep(Duration::from_millis(2100)).await;
        
        // Broadcast #4 - should succeed (rebroadcasts expired message #1)
        let result4 = network_interface.execute_broadcast(peer, false, &mut smp).await;
        assert!(result4.is_ok(), "Broadcast should succeed after expiration");
        
        // Broadcast #5 - should FAIL again (message #1 rebroadcast updated timestamp)
        tokio::time::sleep(Duration::from_millis(100)).await;
        let result5 = network_interface.execute_broadcast(peer, false, &mut smp).await;
        assert!(matches!(result5, Err(BroadcastError::TooManyPendingBroadcasts(_))),
            "New broadcast should fail again after rebroadcast");
        
        // Demonstrate permanent blocking: after multiple cycles, still blocked
        for _ in 0..10 {
            tokio::time::sleep(Duration::from_millis(2100)).await;
            // One rebroadcast succeeds (expired message)
            let _ = network_interface.execute_broadcast(peer, false, &mut smp).await;
            
            // But new broadcasts still blocked
            tokio::time::sleep(Duration::from_millis(100)).await;
            let result = network_interface.execute_broadcast(peer, false, &mut smp).await;
            assert!(matches!(result, Err(BroadcastError::TooManyPendingBroadcasts(_))),
                "Broadcasts remain blocked indefinitely");
        }
    }
}
```

**Steps to reproduce in live network:**
1. Modify an Aptos fullnode to never send `BroadcastTransactionsResponse` messages
2. Connect to a validator or VFN
3. Observe that after 2 broadcasts (validators) or 20 broadcasts (fullnodes), no new transactions are broadcast to the attacker
4. Monitor victim node logs for repeated `TooManyPendingBroadcasts` errors
5. Verify that the same transactions are being rebroadcast cyclically using message IDs

### Citations

**File:** mempool/src/shared_mempool/network.rs (L315-334)
```rust
        if let Some(sent_timestamp) = sync_state.broadcast_info.sent_messages.remove(&message_id) {
            let rtt = timestamp
                .duration_since(sent_timestamp)
                .expect("failed to calculate mempool broadcast RTT");

            let network_id = peer.network_id();
            counters::SHARED_MEMPOOL_BROADCAST_RTT
                .with_label_values(&[network_id.as_str()])
                .observe(rtt.as_secs_f64());

            counters::shared_mempool_pending_broadcasts(&peer).dec();
        } else {
            trace!(
                LogSchema::new(LogEntry::ReceiveACK)
                    .peer(&peer)
                    .message_id(&message_id),
                "request ID does not exist or expired"
            );
            return;
        }
```

**File:** mempool/src/shared_mempool/network.rs (L396-421)
```rust
        // Sync peer's pending broadcasts with latest mempool state.
        // A pending or retry broadcast might become empty if the corresponding txns were committed through
        // another peer, so don't track broadcasts for committed txns.
        let mempool = smp.mempool.lock();
        state.broadcast_info.sent_messages = state
            .broadcast_info
            .sent_messages
            .clone()
            .into_iter()
            .filter(|(message_id, _batch)| {
                !mempool
                    .timeline_range_of_message(message_id.decode())
                    .is_empty()
            })
            .collect::<BTreeMap<MempoolMessageId, SystemTime>>();
        state.broadcast_info.retry_messages = state
            .broadcast_info
            .retry_messages
            .clone()
            .into_iter()
            .filter(|message_id| {
                !mempool
                    .timeline_range_of_message(message_id.decode())
                    .is_empty()
            })
            .collect::<BTreeSet<MempoolMessageId>>();
```

**File:** mempool/src/shared_mempool/network.rs (L426-449)
```rust
        let mut pending_broadcasts = 0;
        let mut expired_message_id = None;

        // Find earliest message in timeline index that expired.
        // Note that state.broadcast_info.sent_messages is ordered in decreasing order in the timeline index
        for (message, sent_time) in state.broadcast_info.sent_messages.iter() {
            let deadline = sent_time.add(Duration::from_millis(
                self.mempool_config.shared_mempool_ack_timeout_ms,
            ));
            if SystemTime::now().duration_since(deadline).is_ok() {
                expired_message_id = Some(message);
            } else {
                pending_broadcasts += 1;
            }

            // The maximum number of broadcasts sent to a single peer that are pending a response ACK at any point.
            // If the number of un-ACK'ed un-expired broadcasts reaches this threshold, we do not broadcast anymore
            // and wait until an ACK is received or a sent broadcast expires.
            // This helps rate-limit egress network bandwidth and not overload a remote peer or this
            // node's network sender.
            if pending_broadcasts >= self.mempool_config.max_broadcasts_per_peer {
                return Err(BroadcastError::TooManyPendingBroadcasts(peer));
            }
        }
```

**File:** mempool/src/shared_mempool/network.rs (L629-633)
```rust
        state
            .broadcast_info
            .sent_messages
            .insert(message_id, send_time);
        Ok(state.broadcast_info.sent_messages.len())
```

**File:** config/src/config/mempool_config.rs (L117-117)
```rust
            max_broadcasts_per_peer: 20,
```

**File:** config/src/config/mempool_config.rs (L199-202)
```rust
            // Set the max_broadcasts_per_peer to 2 (default is 20)
            if local_mempool_config_yaml["max_broadcasts_per_peer"].is_null() {
                mempool_config.max_broadcasts_per_peer = 2;
                modified_config = true;
```
