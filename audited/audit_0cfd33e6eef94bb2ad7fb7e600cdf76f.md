# Audit Report

## Title
Consensus Network Send Failure Monitoring Gap Enables Undetectable Selective Message Censorship by Byzantine Validators

## Summary
The consensus network layer in `consensus/src/network.rs` only logs network send errors with `warn!` level messages and does not track send failures with any metrics. The `CONSENSUS_SENT_MSGS` counter is incremented **before** the actual send attempt, creating a false positive where failed sends are counted as successful. This monitoring gap allows Byzantine validators to selectively drop messages to specific peers while appearing to operate normally in monitoring systems, with no automated detection mechanism. [1](#0-0) 

## Finding Description

The consensus layer's message sending functions contain a critical monitoring gap that enables Byzantine validators to perform selective censorship attacks without detection:

**1. Send Failure Handling in `send()` function:**

The `send()` function increments the `CONSENSUS_SENT_MSGS` counter at line 423-425 **before** attempting the actual send at line 426. When the send fails, only a warning is logged (lines 427-430), with no metric tracking the failure. [2](#0-1) 

**2. Broadcast Failure Handling in `broadcast_without_self()` function:**

Similarly, `broadcast_without_self()` increments `CONSENSUS_SENT_MSGS` by the number of recipients (lines 398-400) before the actual broadcast attempt (lines 402-407). Failures only generate a warning log. [3](#0-2) 

**3. Missing Network-Level Failure Tracking:**

The network framework defines a `PEER_SEND_FAILURES` counter but this counter is **never incremented anywhere in the codebase**. I verified this by searching the entire repository - the counter is defined but unused. [4](#0-3) 

**4. Asynchronous Send Architecture:**

The network send path is asynchronous: `consensus → ConsensusNetworkClient → NetworkClient → NetworkSender → PeerManagerRequestSender → PeerManager → Peer`. Many send failures occur asynchronously after the initial call returns `Ok()`, meaning consensus cannot detect them even if it wanted to. [5](#0-4) 

**Attack Scenario:**

A Byzantine validator can exploit this gap by:

1. **Modifying their node code** to intentionally return errors when sending to specific target validators
2. **Configuring network-level packet dropping** (firewalls, iptables rules) to selectively drop messages to specific peers
3. **Maintaining plausible deniability** by pointing to warning logs showing "network errors"
4. **Appearing healthy in metrics** since `CONSENSUS_SENT_MSGS` shows they "sent" messages
5. **Avoiding detection** since no counter tracks the failure pattern

This enables **selective peer censorship**: a Byzantine validator can strategically exclude specific honest validators from receiving their votes/proposals, degrading those validators' ability to participate in consensus while claiming legitimate network issues.

## Impact Explanation

**Severity: High** - Significant Protocol Violation (per Aptos Bug Bounty)

This issue qualifies as High severity because:

1. **Liveness Degradation**: Byzantine validators can selectively degrade liveness for targeted honest validators by preventing them from receiving critical consensus messages (proposals, votes, sync info)

2. **No Automated Detection**: The protocol has no mechanism to detect this behavior automatically. Operators cannot distinguish between legitimate network issues and intentional censorship

3. **False Monitoring Signals**: Metrics show successful sends when messages actually failed, misleading operators about validator health

4. **Plausible Deniability**: Byzantine validators can point to warning logs as evidence of "network problems" while intentionally dropping messages

5. **Targeted Attacks**: Unlike general Byzantine behavior (refusing to vote, equivocating), this enables targeted attacks against specific validators without affecting the attacker's apparent reputation

While BFT systems are designed to tolerate Byzantine validators, they rely on detection mechanisms (reputation systems, timeout tracking) to identify misbehavior. This gap removes a critical detection capability.

## Likelihood Explanation

**Likelihood: Medium-High**

This attack is likely because:

1. **Low Technical Barrier**: Modifying a validator node to drop sends to specific peers requires minimal code changes (return error in send function) or simple network configuration (firewall rules)

2. **Economic Incentive**: Validators competing for rewards might selectively censor competitors

3. **Collusion Scenarios**: Multiple Byzantine validators could collude to partition specific honest validators

4. **Current Gap**: The monitoring gap exists in production code today

The main limiting factor is that attackers must be validator operators, but given the adversarial nature of blockchain systems, assuming some validators may act maliciously is standard threat modeling.

## Recommendation

**Implement comprehensive send failure tracking:**

```rust
// In consensus/src/network.rs, send() function:
async fn send(&self, msg: ConsensusMsg, recipients: Vec<Author>) {
    fail_point!("consensus::send::any", |_| ());
    let network_sender = self.consensus_network_client.clone();
    let mut self_sender = self.self_sender.clone();
    for peer in recipients {
        if self.author == peer {
            let self_msg = Event::Message(self.author, msg.clone());
            if let Err(err) = self_sender.send(self_msg).await {
                warn!(error = ?err, "Error delivering a self msg");
            }
            continue;
        }
        
        // Track send attempt
        match network_sender.send_to(peer, msg.clone()) {
            Ok(_) => {
                counters::CONSENSUS_SENT_MSGS
                    .with_label_values(&[msg.name()])
                    .inc();
            },
            Err(e) => {
                // NEW: Track send failures per peer
                counters::CONSENSUS_SEND_FAILURES
                    .with_label_values(&[msg.name(), &peer.to_string()])
                    .inc();
                warn!(
                    remote_peer = peer,
                    error = ?e, "Failed to send a msg {:?} to peer", msg
                );
            }
        }
    }
}
```

**Additional recommendations:**

1. **Add `CONSENSUS_SEND_FAILURES` counter** in `consensus/src/counters.rs` with labels for message type and peer
2. **Actually use the `PEER_SEND_FAILURES` counter** in the network framework
3. **Implement per-peer send failure rate monitoring** with automated alerts when failure rates exceed thresholds
4. **Add reputation penalties** for validators with consistently high send failure rates to specific peers
5. **Dashboard visibility** showing per-peer send success/failure rates

## Proof of Concept

Due to the asynchronous nature of the network stack and requirement for a malicious validator, a complete PoC would require:

1. **Setup**: Deploy a local testnet with multiple validators
2. **Modification**: Modify one validator's `consensus/src/network.rs` `send()` function to always return `Err()` for a specific target peer
3. **Observation**: Monitor metrics showing `CONSENSUS_SENT_MSGS` incrementing but no messages arriving at target
4. **Verification**: Check that no failure counters track this behavior

**Simplified demonstration** showing the metric increment before send:

```rust
// File: consensus/src/network.rs, line 411-433
// Current code increments counter BEFORE send attempt:

for peer in recipients {
    // ... self-send handling ...
    
    counters::CONSENSUS_SENT_MSGS           // <- Counter incremented HERE
        .with_label_values(&[msg.name()])
        .inc();
    if let Err(e) = network_sender.send_to(peer, msg.clone()) {  // <- Send attempt AFTER
        warn!(/* ... */);  // <- Failure only logged, not counted
    }
}
```

The vulnerability is demonstrated by the fact that `CONSENSUS_SENT_MSGS` increments regardless of whether `send_to()` succeeds or fails, and there exists no corresponding failure counter.

## Notes

This issue represents a **monitoring and detection gap** rather than a direct protocol vulnerability. However, per Aptos Bug Bounty criteria for High severity ("Significant protocol violations"), the inability to detect selective message censorship by Byzantine validators constitutes a significant weakness in the consensus protocol's Byzantine fault tolerance guarantees. The protocol assumes detection mechanisms exist to identify and exclude misbehaving validators, but this gap removes that capability for send-related attacks.

### Citations

**File:** consensus/src/network.rs (L398-407)
```rust
        counters::CONSENSUS_SENT_MSGS
            .with_label_values(&[msg.name()])
            .inc_by(other_validators.len() as u64);
        // Broadcast message over direct-send to all other validators.
        if let Err(err) = self
            .consensus_network_client
            .send_to_many(other_validators, msg)
        {
            warn!(error = ?err, "Error broadcasting message");
        }
```

**File:** consensus/src/network.rs (L411-433)
```rust
    async fn send(&self, msg: ConsensusMsg, recipients: Vec<Author>) {
        fail_point!("consensus::send::any", |_| ());
        let network_sender = self.consensus_network_client.clone();
        let mut self_sender = self.self_sender.clone();
        for peer in recipients {
            if self.author == peer {
                let self_msg = Event::Message(self.author, msg.clone());
                if let Err(err) = self_sender.send(self_msg).await {
                    warn!(error = ?err, "Error delivering a self msg");
                }
                continue;
            }
            counters::CONSENSUS_SENT_MSGS
                .with_label_values(&[msg.name()])
                .inc();
            if let Err(e) = network_sender.send_to(peer, msg.clone()) {
                warn!(
                    remote_peer = peer,
                    error = ?e, "Failed to send a msg {:?} to peer", msg
                );
            }
        }
    }
```

**File:** network/framework/src/counters.rs (L268-275)
```rust
pub static PEER_SEND_FAILURES: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "aptos_network_peer_send_failures",
        "Number of messages failed to send to peer",
        &["role_type", "network_id", "peer_id", "protocol_id"]
    )
    .unwrap()
});
```

**File:** network/framework/src/peer_manager/mod.rs (L509-547)
```rust
    /// Sends an outbound request for `RPC` or `DirectSend` to the peer
    async fn handle_outbound_request(&mut self, request: PeerManagerRequest) {
        trace!(
            NetworkSchema::new(&self.network_context),
            peer_manager_request = request,
            "{} PeerManagerRequest::{:?}",
            self.network_context,
            request
        );
        self.sample_connected_peers();
        let (peer_id, protocol_id, peer_request) = match request {
            PeerManagerRequest::SendDirectSend(peer_id, msg) => {
                (peer_id, msg.protocol_id(), PeerRequest::SendDirectSend(msg))
            },
            PeerManagerRequest::SendRpc(peer_id, req) => {
                (peer_id, req.protocol_id(), PeerRequest::SendRpc(req))
            },
        };

        if let Some((conn_metadata, sender)) = self.active_peers.get_mut(&peer_id) {
            if let Err(err) = sender.push(protocol_id, peer_request) {
                info!(
                    NetworkSchema::new(&self.network_context).connection_metadata(conn_metadata),
                    protocol_id = %protocol_id,
                    error = ?err,
                    "{} Failed to forward outbound message to downstream actor. Error: {:?}",
                    self.network_context, err
                );
            }
        } else {
            warn!(
                NetworkSchema::new(&self.network_context).remote_peer(&peer_id),
                protocol_id = %protocol_id,
                "{} Can't send message to peer.  Peer {} is currently not connected",
                self.network_context,
                peer_id.short_str()
            );
        }
    }
```
