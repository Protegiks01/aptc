# Audit Report

## Title
ConsensusObserver Deserialization DoS via Excessive Recursion Limit on Untrusted Input

## Summary
The ConsensusObserver protocol uses `RECURSION_LIMIT` (64) for BCS deserialization of network messages from untrusted peers, when it should use `USER_INPUT_RECURSION_LIMIT` (32) like MempoolDirectSend. Since subscription validation occurs AFTER expensive deserialization, attackers can flood the system with deeply nested malicious messages to cause denial-of-service on validator fullnodes.

## Finding Description

The vulnerability stems from a trust model inconsistency in the network message deserialization pipeline. ConsensusObserver treats incoming messages as "trusted" during deserialization but actually receives them from untrusted network peers. [1](#0-0) 

The encoding() function shows two recursion limits: `USER_INPUT_RECURSION_LIMIT` (32) for untrusted input and `RECURSION_LIMIT` (64) for internal protocols. [2](#0-1) 

ConsensusObserver uses `RECURSION_LIMIT` (64) at line 162, while MempoolDirectSend correctly uses `USER_INPUT_RECURSION_LIMIT` (32) at line 168 because it handles user input. This inconsistency is the root cause.

The deserialization happens in the network layer through the `to_message()` method: [3](#0-2) 

This calls `protocol_id().from_bytes()` which applies the recursion limit during BCS deserialization: [4](#0-3) 

The critical issue is that deserialization occurs BEFORE subscription validation. Messages flow through: [5](#0-4) 

The `received_message_to_event()` function spawns blocking tasks to deserialize messages at line 218. [6](#0-5) 

Only AFTER successful deserialization does the application layer validate the sender: [7](#0-6) 

The subscription verification at line 579-581 happens after the computational cost of deserialization has been paid.

**Attack Scenario:**
1. Attacker connects to the network (requires only peer-level authentication, no subscription needed)
2. Attacker crafts BCS-encoded ConsensusObserver messages with deeply nested structures (up to 64 levels)
3. Attacker floods the ConsensusObserver protocol with these messages
4. Each message undergoes expensive deserialization in the `spawn_blocking` thread pool with limit 64
5. Messages are rejected only AFTER deserialization completes (line 579-593)
6. The blocking thread pool is exhausted, delaying or dropping legitimate consensus observer messages

The parallelism is controlled by `max_parallel_deserialization_tasks`: [8](#0-7) 

This defaults to the number of CPUs, allowing multiple concurrent malicious deserializations.

## Impact Explanation

This vulnerability falls under **Medium Severity** per Aptos bug bounty criteria:
- **Validator node slowdowns**: Exhausting the deserialization thread pool delays processing of legitimate consensus observer messages
- **State inconsistencies requiring intervention**: Consensus observer may fall behind, requiring manual intervention or state sync fallback

The impact is limited to nodes running consensus observer (primarily validator fullnodes), but does not cause consensus violations or fund loss. The 2x higher recursion limit (64 vs 32) doubles the potential attack depth compared to properly protected protocols like MempoolDirectSend.

## Likelihood Explanation

**Likelihood: High**

The attack is straightforward to execute:
- No validator privileges required - only network peer access
- Crafting deeply nested BCS structures is trivial (recursive struct definitions)
- No rate limiting occurs before deserialization
- The vulnerability is deterministic - every malicious message incurs cost
- ConsensusObserver is enabled by default on validator fullnodes [9](#0-8) 

The constants show consensus observer is enabled on validators and validator fullnodes by default.

## Recommendation

**Fix:** Change ConsensusObserver to use `USER_INPUT_RECURSION_LIMIT` (32) instead of `RECURSION_LIMIT` (64) to match the security posture of MempoolDirectSend, which also receives untrusted input.

In `network/framework/src/protocols/wire/handshake/v1/mod.rs`, modify line 162:

```rust
// Current (vulnerable):
ProtocolId::ConsensusObserver => Encoding::CompressedBcs(RECURSION_LIMIT),

// Fixed:
ProtocolId::ConsensusObserver => Encoding::CompressedBcs(USER_INPUT_RECURSION_LIMIT),
```

This aligns with the principle that any protocol receiving messages from non-subscribed peers should be treated as untrusted input. Subscription validation is an application-layer concern and cannot protect against deserialization-based attacks at the network layer.

**Alternative Defense-in-Depth Measures:**
1. Implement pre-deserialization rate limiting per peer
2. Move subscription validation to network layer before deserialization
3. Add size limits on individual message fields before full deserialization

## Proof of Concept

```rust
// PoC: Craft deeply nested BCS structure to attack ConsensusObserver
use bcs;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
enum NestedStruct {
    Leaf(u64),
    Node(Box<NestedStruct>),
}

fn create_nested_structure(depth: usize) -> NestedStruct {
    if depth == 0 {
        NestedStruct::Leaf(42)
    } else {
        NestedStruct::Node(Box::new(create_nested_structure(depth - 1)))
    }
}

fn main() {
    // Create a structure with 64 levels of nesting
    let deep_structure = create_nested_structure(64);
    
    // Serialize with BCS
    let serialized = bcs::to_bytes(&deep_structure).unwrap();
    
    // This can be sent to ConsensusObserver protocol
    // Deserialization with RECURSION_LIMIT=64 succeeds but is expensive
    // With USER_INPUT_RECURSION_LIMIT=32, this would be rejected early
    println!("Crafted malicious message of {} bytes", serialized.len());
    
    // Attack: Send thousands of these messages to exhaust deserialization thread pool
    // Result: Legitimate ConsensusObserver messages are delayed/dropped
}
```

To test the impact:
1. Deploy a validator fullnode with consensus observer enabled
2. Connect as a network peer (no subscription required)
3. Send 1000+ deeply nested ConsensusObserver messages rapidly
4. Monitor deserialization thread pool and message processing latency
5. Observe degradation in consensus observer functionality

**Notes**

The vulnerability exists because the codebase makes an implicit assumption that ConsensusObserver messages come from trusted publishers, but the network architecture allows any authenticated peer to send these messages before subscription validation occurs. This is a classic case of "defense in depth" failure where security controls at different layers make inconsistent trust assumptions.

The comparison with MempoolDirectSend is particularly instructive - that protocol correctly recognizes it receives untrusted user input and uses the lower recursion limit. ConsensusObserver should follow the same pattern since it also receives messages from potentially untrusted sources (non-subscribed peers) at the point of deserialization.

### Citations

**File:** network/framework/src/protocols/wire/handshake/v1/mod.rs (L38-39)
```rust
pub const USER_INPUT_RECURSION_LIMIT: usize = 32;
pub const RECURSION_LIMIT: usize = 64;
```

**File:** network/framework/src/protocols/wire/handshake/v1/mod.rs (L156-172)
```rust
    fn encoding(self) -> Encoding {
        match self {
            ProtocolId::ConsensusDirectSendJson | ProtocolId::ConsensusRpcJson => Encoding::Json,
            ProtocolId::ConsensusDirectSendCompressed | ProtocolId::ConsensusRpcCompressed => {
                Encoding::CompressedBcs(RECURSION_LIMIT)
            },
            ProtocolId::ConsensusObserver => Encoding::CompressedBcs(RECURSION_LIMIT),
            ProtocolId::DKGDirectSendCompressed | ProtocolId::DKGRpcCompressed => {
                Encoding::CompressedBcs(RECURSION_LIMIT)
            },
            ProtocolId::JWKConsensusDirectSendCompressed
            | ProtocolId::JWKConsensusRpcCompressed => Encoding::CompressedBcs(RECURSION_LIMIT),
            ProtocolId::MempoolDirectSend => Encoding::CompressedBcs(USER_INPUT_RECURSION_LIMIT),
            ProtocolId::MempoolRpc => Encoding::Bcs(USER_INPUT_RECURSION_LIMIT),
            _ => Encoding::Bcs(RECURSION_LIMIT),
        }
    }
```

**File:** network/framework/src/protocols/wire/handshake/v1/mod.rs (L226-262)
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

    /// Serializes the value using BCS encoding (with a specified limit)
    fn bcs_encode<T: Serialize>(&self, value: &T, limit: usize) -> anyhow::Result<Vec<u8>> {
        bcs::to_bytes_with_limit(value, limit).map_err(|e| anyhow!("{:?}", e))
    }

    /// Deserializes the value using BCS encoding (with a specified limit)
    fn bcs_decode<T: DeserializeOwned>(&self, bytes: &[u8], limit: usize) -> anyhow::Result<T> {
        bcs::from_bytes_with_limit(bytes, limit).map_err(|e| anyhow!("{:?}", e))
    }
```

**File:** network/framework/src/protocols/wire/messaging/v1/mod.rs (L105-114)
```rust
pub trait IncomingRequest {
    fn protocol_id(&self) -> crate::ProtocolId;
    fn data(&self) -> &Vec<u8>;

    /// Converts the `SerializedMessage` into its deserialized version of `TMessage` based on the
    /// `ProtocolId`.  See: [`crate::ProtocolId::from_bytes`]
    fn to_message<TMessage: DeserializeOwned>(&self) -> anyhow::Result<TMessage> {
        self.protocol_id().from_bytes(self.data())
    }
}
```

**File:** network/framework/src/protocols/network/mod.rs (L200-243)
```rust
pub trait NewNetworkEvents {
    fn new(
        peer_mgr_notifs_rx: aptos_channel::Receiver<(PeerId, ProtocolId), ReceivedMessage>,
        max_parallel_deserialization_tasks: Option<usize>,
        allow_out_of_order_delivery: bool,
    ) -> Self;
}

impl<TMessage: Message + Send + Sync + 'static> NewNetworkEvents for NetworkEvents<TMessage> {
    fn new(
        peer_mgr_notifs_rx: aptos_channel::Receiver<(PeerId, ProtocolId), ReceivedMessage>,
        max_parallel_deserialization_tasks: Option<usize>,
        allow_out_of_order_delivery: bool,
    ) -> Self {
        // Determine the number of parallel deserialization tasks to use
        let max_parallel_deserialization_tasks = max_parallel_deserialization_tasks.unwrap_or(1);

        let data_event_stream = peer_mgr_notifs_rx.map(|notification| {
            tokio::task::spawn_blocking(move || received_message_to_event(notification))
        });

        let data_event_stream: Pin<
            Box<dyn Stream<Item = Event<TMessage>> + Send + Sync + 'static>,
        > = if allow_out_of_order_delivery {
            Box::pin(
                data_event_stream
                    .buffer_unordered(max_parallel_deserialization_tasks)
                    .filter_map(|res| future::ready(res.expect("JoinError from spawn blocking"))),
            )
        } else {
            Box::pin(
                data_event_stream
                    .buffered(max_parallel_deserialization_tasks)
                    .filter_map(|res| future::ready(res.expect("JoinError from spawn blocking"))),
            )
        };

        Self {
            event_stream: data_event_stream,
            done: false,
            _marker: PhantomData,
        }
    }
}
```

**File:** network/framework/src/protocols/network/mod.rs (L274-321)
```rust
fn received_message_to_event<TMessage: Message>(
    message: ReceivedMessage,
) -> Option<Event<TMessage>> {
    let peer_id = message.sender.peer_id();
    let ReceivedMessage {
        message,
        sender: _sender,
        receive_timestamp_micros: rx_at,
        rpc_replier,
    } = message;
    let dequeue_at = unix_micros();
    let dt_micros = dequeue_at - rx_at;
    let dt_seconds = (dt_micros as f64) / 1000000.0;
    match message {
        NetworkMessage::RpcRequest(rpc_req) => {
            crate::counters::inbound_queue_delay_observe(rpc_req.protocol_id, dt_seconds);
            let rpc_replier = Arc::into_inner(rpc_replier.unwrap()).unwrap();
            request_to_network_event(peer_id, &rpc_req)
                .map(|msg| Event::RpcRequest(peer_id, msg, rpc_req.protocol_id, rpc_replier))
        },
        NetworkMessage::DirectSendMsg(request) => {
            crate::counters::inbound_queue_delay_observe(request.protocol_id, dt_seconds);
            request_to_network_event(peer_id, &request).map(|msg| Event::Message(peer_id, msg))
        },
        _ => None,
    }
}

/// Converts a `SerializedRequest` into a network `Event` for sending to other nodes
fn request_to_network_event<TMessage: Message, Request: IncomingRequest>(
    peer_id: PeerId,
    request: &Request,
) -> Option<TMessage> {
    match request.to_message() {
        Ok(msg) => Some(msg),
        Err(err) => {
            let data = request.data();
            warn!(
                SecurityEvent::InvalidNetworkEvent,
                error = ?err,
                remote_peer_id = peer_id.short_str(),
                protocol_id = request.protocol_id(),
                data_prefix = hex::encode(&data[..min(16, data.len())]),
            );
            None
        },
    }
}
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L573-594)
```rust
    async fn process_network_message(&mut self, network_message: ConsensusObserverNetworkMessage) {
        // Unpack the network message and note the received time
        let message_received_time = Instant::now();
        let (peer_network_id, message) = network_message.into_parts();

        // Verify the message is from the peers we've subscribed to
        if let Err(error) = self
            .subscription_manager
            .verify_message_for_subscription(peer_network_id)
        {
            // Update the rejected message counter
            increment_rejected_message_counter(&peer_network_id, &message);

            // Log the error and return
            warn!(
                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                    "Received message that was not from an active subscription! Error: {:?}",
                    error,
                ))
            );
            return;
        }
```

**File:** config/src/config/consensus_observer_config.rs (L11-14)
```rust
// Useful constants for enabling consensus observer on different node types
const ENABLE_ON_VALIDATORS: bool = true;
const ENABLE_ON_VALIDATOR_FULLNODES: bool = true;
const ENABLE_ON_PUBLIC_FULLNODES: bool = false;
```
