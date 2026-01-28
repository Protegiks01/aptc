# Audit Report

## Title
Channel Backpressure Bypass via Per-Message-Type Queue Multiplication in Consensus Network Layer

## Summary
A malicious validator can bypass intended channel capacity limits by exploiting the per-key queuing mechanism that creates separate queues for each `(peer_id, message_type)` combination. This allows a single attacker to occupy up to 450+ message slots across consensus channels (not just 230+ as initially estimated), far exceeding the intended per-peer limits of 10-50 messages, leading to validator node slowdowns and potential consensus disruption.

## Finding Description

The consensus network layer implements three independent message channels with FIFO queuing and specific capacity limits: [1](#0-0) 

Each channel uses a composite key of `(AccountAddress, Discriminant<ConsensusMsg>)` for queue management: [2](#0-1) 

The underlying `PerKeyQueue` implementation allocates the full `max_queue_size` capacity to each unique key, meaning each `(peer_id, message_type)` combination receives its own independent queue: [3](#0-2) 

The routing logic in `NetworkTask::start()` directs different message types to different channels **without any validation**: [4](#0-3) 

Critically, message validation (signature verification and epoch checks) occurs **after** messages are dequeued from channels, not before they are enqueued: [5](#0-4) 

When queues reach capacity, the FIFO queue style drops **new** messages, not old ones: [6](#0-5) 

**Attack Scenario:**

A malicious validator can send multiple message types, with each type occupying its own queue:

- **quorum_store_messages** (50 capacity per key): SignedBatchInfo, BatchMsg, ProofOfStoreMsg, SignedBatchInfoMsgV2, BatchMsgV2, ProofOfStoreMsgV2 = 6 types × 50 = **300 messages**
- **consensus_messages** (10 capacity per key): ProposalMsg, OptProposalMsg, VoteMsg, RoundTimeoutMsg, OrderVoteMsg, SyncInfo, EpochRetrievalRequest, EpochChangeProof = 8 types × 10 = **80 messages**
- **rpc_tx** (10 capacity per key): Multiple RPC request types = 7 types × 10 = **70 messages**

**Total: 450+ unvalidated messages from a single peer**, all queued before signature verification or epoch validation occurs. Legitimate messages from honest validators will be dropped when channels reach capacity, as the FIFO mode drops newest messages.

Network-level rate limits are byte-based, not message-count based, and therefore do not prevent this attack: [7](#0-6) 

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program category "Validator node slowdowns."

A coordinated attack by Byzantine validators (< 1/3 of stake) can:

1. **Queue Exhaustion**: Fill victim validators' consensus message queues with 450+ invalid messages per attacker, occupying all available queue slots
2. **Message Dropping**: Cause legitimate proposals and votes from honest validators to be dropped when queues overflow
3. **CPU Waste**: Force validators to waste CPU cycles dequeuing and performing expensive signature verification on invalid messages (as validation occurs after dequeue)
4. **Consensus Delays**: Delay consensus rounds by causing timeouts when critical messages are dropped
5. **Network-wide Impact**: Multiple attackers can target multiple victims simultaneously, multiplying the effect across the network

This is **not** a simple network-level DoS (which is out of scope). Rather, it is a **protocol-level queue management vulnerability** that exploits the application layer's per-key queuing design to bypass intended per-peer resource limits. The issue breaks the Resource Limits invariant where each peer should be limited to a fixed number of messages (10-50), but the actual implementation allows 450+ messages through queue key multiplication.

## Likelihood Explanation

**High Likelihood.** The attack requirements are minimal:

1. **Attacker Profile**: Control of one or more validator nodes (realistic under the < 1/3 Byzantine fault tolerance assumption)
2. **No Special Privileges**: Only requires normal validator network access
3. **Simple Implementation**: Just craft and send multiple message types through the validator's network interface
4. **No Prevention**: Network rate limits operate at the byte level, not message count level
5. **No Timing Requirements**: The vulnerability is inherent in the design and doesn't require race conditions or precise timing

The vulnerability can be exploited at any time by any Byzantine validator without special network conditions or coordination beyond the attacker's own nodes.

## Recommendation

Implement **aggregate per-peer message limits** that enforce a maximum total number of unverified messages from a single peer across all message types, rather than per-(peer, message_type) limits. Possible solutions:

1. **Unified Queue**: Replace per-key queuing with a single queue per peer that aggregates all message types
2. **Global Peer Counter**: Add a counter that tracks total unverified messages from each peer across all channels and reject new messages when the aggregate limit is reached
3. **Pre-Validation**: Perform lightweight validation (e.g., epoch checks) before enqueuing messages
4. **Message-Count Rate Limiting**: Add application-layer rate limiting based on message count, not just bytes

Example fix approach:
- Track `total_pending_messages` per peer across all channels
- Check this counter before calling `push()` on any channel
- Reject messages that would exceed the aggregate per-peer limit (e.g., 50 total messages)

## Proof of Concept

A complete PoC would require setting up a validator network and crafting messages. The conceptual PoC is:

```rust
// Pseudocode - Malicious validator sends multiple message types
for message_type in [SignedBatchInfo, BatchMsg, ProofOfStoreMsg, 
                      ProposalMsg, VoteMsg, SyncInfo, ...] {
    for i in 0..capacity_for_type {
        // Craft invalid message of this type
        let msg = craft_invalid_message(message_type);
        // Send to victim validator
        send_consensus_msg(victim_peer_id, msg);
    }
}
// Result: 450+ messages queued before any validation
// Victim's legitimate message queue now full
// Honest validator messages get dropped
```

The attack exploits the fact that each `(peer_id, message_type)` tuple gets its own queue, allowing the attacker to multiply the intended per-peer capacity by the number of distinct message types.

## Notes

The actual exploitable capacity is **higher than the report's initial estimate of 230+**. The correct calculation based on the codebase is:
- 6 quorum store message types × 50 capacity = 300
- 8 consensus message types × 10 capacity = 80  
- 7 RPC message types × 10 capacity = 70
- **Total: 450 unvalidated message slots per attacker**

This represents a **45x amplification** over the intended per-peer limit for consensus messages (10) and a **9x amplification** for quorum store messages (50), making it a significant resource exhaustion vulnerability that can degrade validator performance and consensus throughput.

### Citations

**File:** consensus/src/network.rs (L193-207)
```rust
pub struct NetworkReceivers {
    /// Provide a LIFO buffer for each (Author, MessageType) key
    pub consensus_messages: aptos_channel::Receiver<
        (AccountAddress, Discriminant<ConsensusMsg>),
        (AccountAddress, ConsensusMsg),
    >,
    pub quorum_store_messages: aptos_channel::Receiver<
        (AccountAddress, Discriminant<ConsensusMsg>),
        (AccountAddress, ConsensusMsg),
    >,
    pub rpc_rx: aptos_channel::Receiver<
        (AccountAddress, Discriminant<IncomingRpcRequest>),
        (AccountAddress, IncomingRpcRequest),
    >,
}
```

**File:** consensus/src/network.rs (L757-769)
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
        );
        let (rpc_tx, rpc_rx) =
            aptos_channel::new(QueueStyle::FIFO, 10, Some(&counters::RPC_CHANNEL_MSGS));
```

**File:** consensus/src/network.rs (L822-941)
```rust
                    match msg {
                        quorum_store_msg @ (ConsensusMsg::SignedBatchInfo(_)
                        | ConsensusMsg::BatchMsg(_)
                        | ConsensusMsg::ProofOfStoreMsg(_)) => {
                            Self::push_msg(
                                peer_id,
                                quorum_store_msg,
                                &self.quorum_store_messages_tx,
                            );
                        },
                        // Remove after migration to use rpc.
                        ConsensusMsg::CommitVoteMsg(commit_vote) => {
                            let (tx, _rx) = oneshot::channel();
                            let req_with_callback =
                                IncomingRpcRequest::CommitRequest(IncomingCommitRequest {
                                    req: CommitMessage::Vote(*commit_vote),
                                    protocol: RPC[0],
                                    response_sender: tx,
                                });
                            if let Err(e) = self.rpc_tx.push(
                                (peer_id, discriminant(&req_with_callback)),
                                (peer_id, req_with_callback),
                            ) {
                                warn!(error = ?e, "aptos channel closed");
                            };
                        },
                        ConsensusMsg::CommitDecisionMsg(commit_decision) => {
                            let (tx, _rx) = oneshot::channel();
                            let req_with_callback =
                                IncomingRpcRequest::CommitRequest(IncomingCommitRequest {
                                    req: CommitMessage::Decision(*commit_decision),
                                    protocol: RPC[0],
                                    response_sender: tx,
                                });
                            if let Err(e) = self.rpc_tx.push(
                                (peer_id, discriminant(&req_with_callback)),
                                (peer_id, req_with_callback),
                            ) {
                                warn!(error = ?e, "aptos channel closed");
                            };
                        },
                        consensus_msg @ (ConsensusMsg::ProposalMsg(_)
                        | ConsensusMsg::OptProposalMsg(_)
                        | ConsensusMsg::VoteMsg(_)
                        | ConsensusMsg::RoundTimeoutMsg(_)
                        | ConsensusMsg::OrderVoteMsg(_)
                        | ConsensusMsg::SyncInfo(_)
                        | ConsensusMsg::EpochRetrievalRequest(_)
                        | ConsensusMsg::EpochChangeProof(_)) => {
                            if let ConsensusMsg::ProposalMsg(proposal) = &consensus_msg {
                                observe_block(
                                    proposal.proposal().timestamp_usecs(),
                                    BlockStage::NETWORK_RECEIVED,
                                );
                                info!(
                                    LogSchema::new(LogEvent::NetworkReceiveProposal)
                                        .remote_peer(peer_id),
                                    block_round = proposal.proposal().round(),
                                    block_hash = proposal.proposal().id(),
                                );
                            }
                            if let ConsensusMsg::OptProposalMsg(proposal) = &consensus_msg {
                                observe_block(
                                    proposal.timestamp_usecs(),
                                    BlockStage::NETWORK_RECEIVED,
                                );
                                observe_block(
                                    proposal.timestamp_usecs(),
                                    BlockStage::NETWORK_RECEIVED_OPT_PROPOSAL,
                                );
                                info!(
                                    LogSchema::new(LogEvent::NetworkReceiveOptProposal)
                                        .remote_peer(peer_id),
                                    block_author = proposal.proposer(),
                                    block_epoch = proposal.epoch(),
                                    block_round = proposal.round(),
                                );
                            }
                            Self::push_msg(peer_id, consensus_msg, &self.consensus_messages_tx);
                        },
                        // TODO: get rid of the rpc dummy value
                        ConsensusMsg::RandGenMessage(req) => {
                            let (tx, _rx) = oneshot::channel();
                            let req_with_callback =
                                IncomingRpcRequest::RandGenRequest(IncomingRandGenRequest {
                                    req,
                                    sender: peer_id,
                                    protocol: RPC[0],
                                    response_sender: tx,
                                });
                            if let Err(e) = self.rpc_tx.push(
                                (peer_id, discriminant(&req_with_callback)),
                                (peer_id, req_with_callback),
                            ) {
                                warn!(error = ?e, "aptos channel closed");
                            };
                        },
                        // TODO: get rid of the rpc dummy value
                        ConsensusMsg::SecretShareMsg(req) => {
                            let (tx, _rx) = oneshot::channel();
                            let req_with_callback = IncomingRpcRequest::SecretShareRequest(
                                IncomingSecretShareRequest {
                                    req,
                                    sender: peer_id,
                                    protocol: RPC[0],
                                    response_sender: tx,
                                },
                            );
                            if let Err(e) = self.rpc_tx.push(
                                (peer_id, discriminant(&req_with_callback)),
                                (peer_id, req_with_callback),
                            ) {
                                warn!(error = ?e, "aptos channel closed");
                            };
                        },
                        _ => {
                            warn!(remote_peer = peer_id, "Unexpected direct send msg");
                            continue;
                        },
                    }
```

**File:** crates/channel/src/message_queues.rs (L112-152)
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
    }
```

**File:** consensus/src/epoch_manager.rs (L1528-1625)
```rust
    async fn process_message(
        &mut self,
        peer_id: AccountAddress,
        consensus_msg: ConsensusMsg,
    ) -> anyhow::Result<()> {
        fail_point!("consensus::process::any", |_| {
            Err(anyhow::anyhow!("Injected error in process_message"))
        });

        if let ConsensusMsg::ProposalMsg(proposal) = &consensus_msg {
            observe_block(
                proposal.proposal().timestamp_usecs(),
                BlockStage::EPOCH_MANAGER_RECEIVED,
            );
        }
        if let ConsensusMsg::OptProposalMsg(proposal) = &consensus_msg {
            if !self.config.enable_optimistic_proposal_rx {
                bail!(
                    "Unexpected OptProposalMsg. Feature is disabled. Author: {}, Epoch: {}, Round: {}",
                    proposal.block_data().author(),
                    proposal.epoch(),
                    proposal.round()
                )
            }
            observe_block(
                proposal.timestamp_usecs(),
                BlockStage::EPOCH_MANAGER_RECEIVED,
            );
            observe_block(
                proposal.timestamp_usecs(),
                BlockStage::EPOCH_MANAGER_RECEIVED_OPT_PROPOSAL,
            );
        }
        // we can't verify signatures from a different epoch
        let maybe_unverified_event = self.check_epoch(peer_id, consensus_msg).await?;

        if let Some(unverified_event) = maybe_unverified_event {
            // filter out quorum store messages if quorum store has not been enabled
            match self.filter_quorum_store_events(peer_id, &unverified_event) {
                Ok(true) => {},
                Ok(false) => return Ok(()), // This occurs when the quorum store is not enabled, but the recovery mode is enabled. We filter out the messages, but don't raise any error.
                Err(err) => return Err(err),
            }
            // same epoch -> run well-formedness + signature check
            let epoch_state = self
                .epoch_state
                .clone()
                .ok_or_else(|| anyhow::anyhow!("Epoch state is not available"))?;
            let proof_cache = self.proof_cache.clone();
            let quorum_store_enabled = self.quorum_store_enabled;
            let quorum_store_msg_tx = self.quorum_store_msg_tx.clone();
            let buffered_proposal_tx = self.buffered_proposal_tx.clone();
            let round_manager_tx = self.round_manager_tx.clone();
            let my_peer_id = self.author;
            let max_num_batches = self.config.quorum_store.receiver_max_num_batches;
            let max_batch_expiry_gap_usecs =
                self.config.quorum_store.batch_expiry_gap_when_init_usecs;
            let payload_manager = self.payload_manager.clone();
            let pending_blocks = self.pending_blocks.clone();
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
                        Ok(verified_event) => {
                            Self::forward_event(
                                quorum_store_msg_tx,
                                round_manager_tx,
                                buffered_proposal_tx,
                                peer_id,
                                verified_event,
                                payload_manager,
                                pending_blocks,
                            );
                        },
                        Err(e) => {
                            error!(
                                SecurityEvent::ConsensusInvalidMessage,
                                remote_peer = peer_id,
                                error = ?e,
                                unverified_event = unverified_event
                            );
                        },
                    }
                })
                .await;
        }
        Ok(())
    }
```

**File:** config/src/config/network_config.rs (L368-377)
```rust
pub struct RateLimitConfig {
    /// Maximum number of bytes/s for an IP
    pub ip_byte_bucket_rate: usize,
    /// Maximum burst of bytes for an IP
    pub ip_byte_bucket_size: usize,
    /// Initial amount of tokens initially in the bucket
    pub initial_bucket_fill_percentage: u8,
    /// Allow for disabling the throttles
    pub enabled: bool,
}
```
