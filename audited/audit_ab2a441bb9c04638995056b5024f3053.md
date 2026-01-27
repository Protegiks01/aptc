# Audit Report

## Title
Memory Exhaustion Vulnerability in aptos_channel Due to Unbounded Message Sizes Leading to Validator OOM Crashes

## Summary
The `aptos_channel` implementation has no trait bounds on the generic message type `M`, allowing extremely large messages (up to 64MB based on network limits) to be queued in memory before size validation occurs. This enables malicious validators to exhaust memory on honest validators by flooding them with oversized consensus messages, potentially causing OOM crashes and consensus liveness failures.

## Finding Description

The vulnerability exists in the consensus message handling pipeline where size validation occurs **after** messages are queued rather than before.

**Root Cause:** The `aptos_channel` generic type has no size bounds [1](#0-0) , and messages are stored directly in a `VecDeque` without any size validation [2](#0-1) .

**Attack Flow:**

1. The network layer allows messages up to 64MB [3](#0-2) 

2. When consensus messages arrive from the network, they are immediately pushed to the `aptos_channel` queue **before** any size validation [4](#0-3) 

3. Messages are queued per `(AccountAddress, Discriminant<ConsensusMsg>)` key with max capacities of 10 for consensus messages and 50 for quorum store messages [5](#0-4) 

4. Size validation only occurs later when processing the proposal, after the message has been dequeued [6](#0-5) 

5. The epoch manager's event loop consumes messages from the queue only after they've been fully stored in memory [7](#0-6) 

**Exploitation Scenario:**

A malicious validator can send `ProposalMsg` containing blocks with transaction payloads up to 6MB (consensus receiving limit) or even attempt 64MB messages (network limit). Messages like `Payload::DirectMempool(Vec<SignedTransaction>)` or inline batches contain full transaction data [8](#0-7) .

**Memory Calculation:**
- Single malicious validator, consensus messages: 10 messages × 6MB = 60MB per message type
- Single malicious validator, quorum store messages: 50 messages × 6MB = 300MB per message type  
- Multiple malicious validators (e.g., 10): 10 × 300MB = 3GB just for quorum store messages
- Multiple message types per validator: Could use `ProposalMsg`, `BatchMsg`, `ProofOfStoreMsg`, etc., multiplying memory usage

This breaks the **Resource Limits** invariant that all operations must respect memory constraints.

## Impact Explanation

This is a **High Severity** vulnerability per Aptos bug bounty criteria:

- **Validator node slowdowns**: Memory pressure causes performance degradation
- **Potential validator crashes**: OOM conditions can crash validator processes
- **Consensus liveness impact**: If multiple validators crash or slow down simultaneously, consensus may stall

The impact qualifies as High rather than Critical because:
- It requires compromised validators (within the Byzantine threat model of <1/3 malicious validators)
- It doesn't directly cause fund loss or permanent state corruption
- Recovery is possible by restarting affected validators
- It affects availability rather than safety

However, in a large validator set with multiple compromised validators coordinating an attack, the impact could be severe enough to temporarily halt network progress.

## Likelihood Explanation

**Likelihood: Medium-High**

The attack is likely because:
- AptosBFT is designed to tolerate up to 1/3 Byzantine validators, so malicious validators are within the threat model
- No special privileges beyond being a validator are required
- The attack is straightforward: simply send oversized messages
- Detection may be delayed since messages appear valid until processing
- No cryptographic or complex technical barriers exist

Mitigating factors:
- Requires control of one or more validator nodes
- Network bandwidth limitations may slow the attack
- Monitoring systems might detect unusual memory consumption patterns

## Recommendation

Implement size validation **before** queuing messages in `aptos_channel`:

1. **Add size limits to channel configuration:**
```rust
pub struct Config {
    pub queue_style: QueueStyle,
    pub max_capacity: usize,
    pub max_message_size_bytes: Option<usize>, // Add this
    pub counters: Option<&'static IntCounterVec>,
}
```

2. **Validate message size before pushing:**
```rust
pub fn push_with_feedback(
    &self,
    key: K,
    message: M,
    status_ch: Option<oneshot::Sender<ElementStatus<M>>>,
) -> Result<()> {
    let mut shared_state = self.shared_state.lock();
    ensure!(!shared_state.receiver_dropped, "Channel is closed");
    
    // Add size check before queuing
    if let Some(max_size) = self.max_message_size_bytes {
        let message_size = std::mem::size_of_val(&message);
        ensure!(message_size <= max_size, "Message exceeds size limit");
    }
    
    let dropped = shared_state.internal_queue.push(key, (message, status_ch));
    // ... rest of implementation
}
```

3. **Apply appropriate limits in consensus network setup:**
```rust
aptos_channel::Config::new(node_config.consensus.max_network_channel_size)
    .queue_style(QueueStyle::FIFO)
    .max_message_size_bytes(Some(6 * 1024 * 1024)) // 6MB consensus limit
    .counters(&aptos_consensus::counters::PENDING_CONSENSUS_NETWORK_EVENTS)
```

4. **Add early rejection in NetworkTask before queuing:**
Validate message sizes immediately after deserialization and before calling `push_msg()`.

## Proof of Concept

```rust
// Reproduction test for consensus/src/network_tests.rs

#[tokio::test]
async fn test_memory_exhaustion_via_oversized_messages() {
    use aptos_consensus_types::proposal_msg::ProposalMsg;
    use aptos_types::transaction::SignedTransaction;
    
    // Setup network task and channels
    let (network_task, mut network_receivers) = NetworkTask::new(
        network_service_events,
        self_receiver,
    );
    
    // Create an oversized proposal with many transactions
    let mut large_txns = Vec::new();
    for _ in 0..10000 {
        large_txns.push(create_large_transaction()); // ~600 bytes each = 6MB total
    }
    
    let oversized_proposal = create_proposal_with_txns(large_txns);
    let oversized_msg = ConsensusMsg::ProposalMsg(Box::new(oversized_proposal));
    
    // Simulate malicious validator sending 10 oversized messages rapidly
    let malicious_peer = AccountAddress::random();
    for _ in 0..10 {
        network_task.push_msg(
            malicious_peer,
            oversized_msg.clone(),
            &network_task.consensus_messages_tx,
        );
    }
    
    // Verify messages are queued (consuming ~60MB memory)
    // Before validation would occur
    let memory_before = get_process_memory();
    
    // Messages stay queued until consumed
    tokio::time::sleep(Duration::from_secs(1)).await;
    
    let memory_after = get_process_memory();
    assert!(memory_after - memory_before > 50_000_000); // >50MB consumed
    
    // Now try with 10 malicious validators
    for _ in 0..10 {
        let peer = AccountAddress::random();
        for _ in 0..10 {
            network_task.push_msg(peer, oversized_msg.clone(), &network_task.consensus_messages_tx);
        }
    }
    
    // Total memory: 10 peers × 10 messages × 6MB = 600MB
    // This can cause OOM on validators with limited memory
}
```

## Notes

This vulnerability is particularly concerning in production environments where:
- Validator nodes may have memory constraints (e.g., 16-32GB RAM)
- Multiple malicious validators could coordinate attacks
- Combined with other memory-intensive operations (state sync, execution), OOM becomes more likely

The fix should be implemented defensively at multiple layers:
1. Network layer: Enforce stricter message size limits before deserialization
2. Channel layer: Add configurable size bounds and reject oversized messages early
3. Application layer: Continue existing validation but as defense-in-depth

Additionally, consider adding monitoring for unusual memory growth patterns in the channel queues to detect potential attacks in progress.

### Citations

**File:** crates/channel/src/aptos_channel.rs (L29-31)
```rust
struct SharedState<K: Eq + Hash + Clone, M> {
    /// The internal queue of messages in this channel.
    internal_queue: PerKeyQueue<K, (M, Option<oneshot::Sender<ElementStatus<M>>>)>,
```

**File:** crates/channel/src/message_queues.rs (L112-151)
```rust
    pub(crate) fn push(&mut self, key: K, message: T) -> Option<T> {
        if let Some(c) = self.counters.as_ref() {
            c.with_label_values(&["enqueued"]).inc();
        }

        let key_message_queue = self
            .per_key_queue
            .entry(key.clone())
            // Only allocate a small initial queue for a new key. Previously, we
            // allocated a queue with all `max_queue_size_per_key` entries;
            // however, this breaks down when we have lots of transient peers.
            // For example, many of our queues have a max capacity of 1024. To
            // handle a single rpc from a transient peer, we would end up
            // allocating ~ 96 b * 1024 ~ 64 Kib per queue.
            .or_insert_with(|| VecDeque::with_capacity(1));

        // Add the key to our round-robin queue if it's not already there
        if key_message_queue.is_empty() {
            self.round_robin_queue.push_back(key);
        }

        // Push the message to the actual key message queue
        if key_message_queue.len() >= self.max_queue_size.get() {
            if let Some(c) = self.counters.as_ref() {
                c.with_label_values(&["dropped"]).inc();
            }
            match self.queue_style {
                // Drop the newest message for FIFO
                QueueStyle::FIFO => Some(message),
                // Drop the oldest message for LIFO
                QueueStyle::LIFO | QueueStyle::KLAST => {
                    let oldest = key_message_queue.pop_front();
                    key_message_queue.push_back(message);
                    oldest
                },
            }
        } else {
            key_message_queue.push_back(message);
            None
        }
```

**File:** config/src/config/network_config.rs (L50-50)
```rust
pub const MAX_MESSAGE_SIZE: usize = 64 * 1024 * 1024; /* 64 MiB */
```

**File:** consensus/src/network.rs (L757-766)
```rust
        let (consensus_messages_tx, consensus_messages) = aptos_channel::new(
            QueueStyle::FIFO,
            10,
            Some(&counters::CONSENSUS_CHANNEL_MSGS),
        );
        let (quorum_store_messages_tx, quorum_store_messages) = aptos_channel::new(
            QueueStyle::FIFO,
            // TODO: tune this value based on quorum store messages with backpressure
            50,
            Some(&counters::QUORUM_STORE_CHANNEL_MSGS),
```

**File:** consensus/src/network.rs (L799-813)
```rust
    fn push_msg(
        peer_id: AccountAddress,
        msg: ConsensusMsg,
        tx: &aptos_channel::Sender<
            (AccountAddress, Discriminant<ConsensusMsg>),
            (AccountAddress, ConsensusMsg),
        >,
    ) {
        if let Err(e) = tx.push((peer_id, discriminant(&msg)), (peer_id, msg)) {
            warn!(
                remote_peer = peer_id,
                error = ?e, "Error pushing consensus msg",
            );
        }
    }
```

**File:** consensus/src/round_manager.rs (L1187-1193)
```rust
        ensure!(
            validator_txns_total_bytes + payload_size as u64
                <= self.local_config.max_receiving_block_bytes,
            "Payload size {} exceeds the limit {}",
            payload_size,
            self.local_config.max_receiving_block_bytes,
        );
```

**File:** consensus/src/epoch_manager.rs (L1931-1936)
```rust
                (peer, msg) = network_receivers.consensus_messages.select_next_some() => {
                    monitor!("epoch_manager_process_consensus_messages",
                    if let Err(e) = self.process_message(peer, msg).await {
                        error!(epoch = self.epoch(), error = ?e, kind = error_kind(&e));
                    });
                },
```

**File:** consensus/consensus-types/src/common.rs (L209-224)
```rust
pub enum Payload {
    DirectMempool(Vec<SignedTransaction>),
    InQuorumStore(ProofWithData),
    InQuorumStoreWithLimit(ProofWithDataWithTxnLimit),
    QuorumStoreInlineHybrid(
        Vec<(BatchInfo, Vec<SignedTransaction>)>,
        ProofWithData,
        Option<u64>,
    ),
    OptQuorumStore(OptQuorumStorePayload),
    QuorumStoreInlineHybridV2(
        Vec<(BatchInfo, Vec<SignedTransaction>)>,
        ProofWithData,
        PayloadExecutionLimit,
    ),
}
```
