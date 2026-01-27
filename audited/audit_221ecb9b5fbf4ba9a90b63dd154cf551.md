# Audit Report

## Title
RPC Request Replay Attack Enabling Resource Exhaustion via Missing Request-ID Deduplication

## Summary
The `RpcRequest` structure lacks replay protection mechanisms (timestamp, nonce, or request-ID tracking), allowing malicious peers to replay identical RPC requests multiple times. While application-layer deduplication prevents state inconsistencies for most message types, the network layer still processes each replay through deserialization, verification, and routing, enabling resource exhaustion attacks against validator nodes.

## Finding Description

The `RpcRequest` structure contains only a sender-controlled `request_id` field without any replay protection: [1](#0-0) 

The `InboundRpcs` handler processes incoming RPC requests without tracking previously seen request IDs: [2](#0-1) 

When an RPC request arrives, the system:
1. Deserializes the request from the wire
2. Creates an `InboundRpc` task (up to `max_concurrent_inbound_rpcs` limit)
3. Forwards to the application handler via `peer_notifs_tx.push()`
4. Performs signature verification (for DAG messages)
5. Routes to appropriate handler in EpochManager [3](#0-2) [4](#0-3) 

**Attack Scenario:**
1. Attacker (malicious validator or compromised peer) sends `RpcRequest` with `request_id=999` and `protocol_id=ConsensusRpc`
2. Victim node processes the request normally
3. Attacker replays the same `RpcRequest` with identical `request_id=999` hundreds of times
4. Each replay is accepted because `InboundRpcs` has no request-ID deduplication
5. Each replay consumes resources: network bandwidth, CPU for deserialization/verification, task queue slots

**Mitigating Factors:**
Application-layer deduplication exists for some message types:
- DAG messages have content-based deduplication (round, author) in `NodeBroadcastHandler` and `DagDriver`
- Block retrieval uses KLAST queue style which keeps only the latest request per peer

However, this doesn't prevent the network/RPC layer from wasting resources on each replay before reaching application-level deduplication.

## Impact Explanation

This vulnerability enables **resource exhaustion attacks** against validator nodes, qualifying as **High Severity** under "Validator node slowdowns" per Aptos bug bounty criteria.

**Resource Impact:**
- **Network bandwidth**: Each replayed request must be received and deserialized
- **CPU cycles**: BCS deserialization, signature verification for DAG messages
- **Memory**: Each request creates an `InboundRpc` task that persists until timeout
- **Task queue saturation**: The `max_concurrent_inbound_rpcs` limit (typically 32) can be filled with replayed requests, causing legitimate requests to be dropped with `DECLINED_LABEL` [5](#0-4) 

While application layers prevent state inconsistencies through content-based deduplication, the RPC layer's lack of replay protection violates the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits."

## Likelihood Explanation

**Attack Requirements:**
- Attacker must be able to send RPC messages to validator nodes (requires being a validator or having network access to validator P2P layer)
- Attacker can capture legitimate RPC requests via network sniffing or by being a legitimate peer
- No special cryptographic material needed beyond normal peer authentication

**Likelihood: MEDIUM**
- In permissioned validator networks, attack requires validator access or compromise
- In networks with relaxed peer policies, external attackers could exploit this
- Attack is simple: capture and replay existing RPC messages
- Detection is difficult as replays appear as legitimate traffic initially

## Recommendation

Implement request-ID tracking in `InboundRpcs` to detect and drop replayed requests:

```rust
pub struct InboundRpcs {
    network_context: NetworkContext,
    time_service: TimeService,
    remote_peer_id: PeerId,
    inbound_rpc_tasks: FuturesUnordered<...>,
    inbound_rpc_timeout: Duration,
    max_concurrent_inbound_rpcs: u32,
    
    // NEW: Track recently processed request IDs
    processed_request_ids: Arc<Mutex<HashMap<RequestId, Instant>>>,
    request_id_ttl: Duration,
}

impl InboundRpcs {
    pub fn handle_inbound_request(...) -> Result<(), RpcError> {
        let request_id = rpc_request.request_id;
        
        // Check for duplicate request_id
        let mut processed = self.processed_request_ids.lock();
        if let Some(&last_seen) = processed.get(&request_id) {
            if self.time_service.now().duration_since(last_seen) < self.request_id_ttl {
                counters::rpc_messages(
                    network_context,
                    REQUEST_LABEL,
                    INBOUND_LABEL,
                    "DUPLICATE_LABEL"
                ).inc();
                return Err(RpcError::DuplicateRequestId(request_id));
            }
        }
        
        // Track this request_id
        processed.insert(request_id, self.time_service.now());
        
        // Periodically garbage collect old entries
        if processed.len() > 1000 {
            processed.retain(|_, &mut last_seen| {
                self.time_service.now().duration_since(last_seen) < self.request_id_ttl
            });
        }
        
        // Continue with existing logic...
    }
}
```

**Alternative:** Add timestamp to `RpcRequest` structure and reject requests older than a threshold (requires protocol change).

## Proof of Concept

```rust
#[cfg(test)]
mod replay_attack_test {
    use super::*;
    use aptos_channels::aptos_channel;
    use aptos_config::network_id::NetworkContext;
    use aptos_time_service::TimeService;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_rpc_request_replay_accepted() {
        // Setup
        let network_context = NetworkContext::mock();
        let time_service = TimeService::mock();
        let remote_peer_id = PeerId::random();
        let mut inbound_rpcs = InboundRpcs::new(
            network_context,
            time_service,
            remote_peer_id,
            Duration::from_secs(30),
            10, // max_concurrent_inbound_rpcs
        );
        
        let (peer_notifs_tx, _peer_notifs_rx) = aptos_channel::new(
            QueueStyle::FIFO, 
            10, 
            None
        );
        
        // Create RPC request
        let rpc_request = RpcRequest {
            protocol_id: ProtocolId::ConsensusRpcBcs,
            request_id: 123, // Attacker-controlled ID
            priority: 0,
            raw_request: vec![1, 2, 3],
        };
        
        let message = NetworkMessage::RpcRequest(rpc_request.clone());
        let received_msg = ReceivedMessage::new(
            message.clone(),
            PeerNetworkId::new(NetworkId::Validator, remote_peer_id)
        );
        
        // First request should succeed
        let result1 = inbound_rpcs.handle_inbound_request(
            &peer_notifs_tx, 
            received_msg.clone()
        );
        assert!(result1.is_ok(), "First request should be accepted");
        
        // REPLAY: Same request_id=123 should ALSO succeed (vulnerability!)
        let received_msg2 = ReceivedMessage::new(
            message.clone(),
            PeerNetworkId::new(NetworkId::Validator, remote_peer_id)
        );
        let result2 = inbound_rpcs.handle_inbound_request(
            &peer_notifs_tx, 
            received_msg2
        );
        
        // BUG: Replay is accepted without deduplication
        assert!(result2.is_ok(), 
            "Replay with same request_id accepted - VULNERABILITY!");
        
        // Can replay multiple times up to concurrent limit
        for i in 0..8 {
            let msg = ReceivedMessage::new(
                message.clone(),
                PeerNetworkId::new(NetworkId::Validator, remote_peer_id)
            );
            let result = inbound_rpcs.handle_inbound_request(&peer_notifs_tx, msg);
            assert!(result.is_ok(), 
                "Replay {} accepted - resource exhaustion possible", i);
        }
    }
}
```

## Notes

While application-layer handlers (DAG, block retrieval) implement content-based deduplication that prevents state inconsistencies, the RPC layer's lack of replay protection creates an exploitable resource exhaustion vector. This violates defense-in-depth principles and the Resource Limits invariant. The vulnerability is exploitable by any peer with network access to validator nodes, making it a realistic attack surface for malicious actors seeking to degrade validator performance.

### Citations

**File:** network/framework/src/protocols/wire/messaging/v1/mod.rs (L116-128)
```rust
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub struct RpcRequest {
    /// `protocol_id` is a variant of the ProtocolId enum.
    pub protocol_id: ProtocolId,
    /// RequestId for the RPC Request.
    pub request_id: RequestId,
    /// Request priority in the range 0..=255.
    pub priority: Priority,
    /// Request payload. This will be parsed by the application-level handler.
    #[serde(with = "serde_bytes")]
    pub raw_request: Vec<u8>,
}
```

**File:** network/framework/src/protocols/rpc/mod.rs (L204-288)
```rust
    /// Handle a new inbound `RpcRequest` message off the wire.
    pub fn handle_inbound_request(
        &mut self,
        peer_notifs_tx: &aptos_channel::Sender<(PeerId, ProtocolId), ReceivedMessage>,
        mut request: ReceivedMessage,
    ) -> Result<(), RpcError> {
        let network_context = &self.network_context;

        // Drop new inbound requests if our completion queue is at capacity.
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
        }

        let peer_id = request.sender.peer_id();
        let NetworkMessage::RpcRequest(rpc_request) = &request.message else {
            return Err(RpcError::InvalidRpcResponse);
        };
        let protocol_id = rpc_request.protocol_id;
        let request_id = rpc_request.request_id;
        let priority = rpc_request.priority;

        trace!(
            NetworkSchema::new(network_context).remote_peer(&self.remote_peer_id),
            "{} Received inbound rpc request from peer {} with request_id {} and protocol_id {}",
            network_context,
            self.remote_peer_id.short_str(),
            request_id,
            protocol_id,
        );
        self.update_inbound_rpc_request_metrics(protocol_id, rpc_request.raw_request.len() as u64);

        let timer =
            counters::inbound_rpc_handler_latency(network_context, protocol_id).start_timer();

        // Forward request to PeerManager for handling.
        let (response_tx, response_rx) = oneshot::channel();
        request.rpc_replier = Some(Arc::new(response_tx));
        if let Err(err) = peer_notifs_tx.push((peer_id, protocol_id), request) {
            counters::rpc_messages(network_context, REQUEST_LABEL, INBOUND_LABEL, FAILED_LABEL)
                .inc();
            return Err(err.into());
        }

        // Create a new task that waits for a response from the upper layer with a timeout.
        let inbound_rpc_task = self
            .time_service
            .timeout(self.inbound_rpc_timeout, response_rx)
            .map(move |result| {
                // Flatten the errors
                let maybe_response = match result {
                    Ok(Ok(Ok(response_bytes))) => {
                        let rpc_response = RpcResponse {
                            request_id,
                            priority,
                            raw_response: Vec::from(response_bytes.as_ref()),
                        };
                        Ok((rpc_response, protocol_id))
                    },
                    Ok(Ok(Err(err))) => Err(err),
                    Ok(Err(oneshot::Canceled)) => Err(RpcError::UnexpectedResponseChannelCancel),
                    Err(timeout::Elapsed) => Err(RpcError::TimedOut),
                };
                // Only record latency of successful requests
                match maybe_response {
                    Ok(_) => timer.stop_and_record(),
                    Err(_) => timer.stop_and_discard(),
                };
                maybe_response
            })
            .boxed();

        // Add that task to the inbound completion queue. These tasks are driven
        // forward by `Peer` awaiting `self.next_completed_response()`.
        self.inbound_rpc_tasks.push(inbound_rpc_task);

        Ok(())
    }
```

**File:** network/framework/src/peer/mod.rs (L505-530)
```rust
            NetworkMessage::RpcRequest(request) => {
                match self.upstream_handlers.get(&request.protocol_id) {
                    None => {
                        counters::direct_send_messages(&self.network_context, UNKNOWN_LABEL).inc();
                        counters::direct_send_bytes(&self.network_context, UNKNOWN_LABEL)
                            .inc_by(request.raw_request.len() as u64);
                    },
                    Some(handler) => {
                        let sender = self.connection_metadata.remote_peer_id;
                        let network_id = self.network_context.network_id();
                        let sender = PeerNetworkId::new(network_id, sender);
                        if let Err(err) = self
                            .inbound_rpcs
                            .handle_inbound_request(handler, ReceivedMessage::new(message, sender))
                        {
                            warn!(
                                NetworkSchema::new(&self.network_context)
                                    .connection_metadata(&self.connection_metadata),
                                error = %err,
                                "{} Error handling inbound rpc request: {}",
                                self.network_context,
                                err
                            );
                        }
                    },
                }
```

**File:** consensus/src/epoch_manager.rs (L1806-1893)
```rust
    fn process_rpc_request(
        &mut self,
        peer_id: Author,
        request: IncomingRpcRequest,
    ) -> anyhow::Result<()> {
        fail_point!("consensus::process::any", |_| {
            Err(anyhow::anyhow!("Injected error in process_rpc_request"))
        });

        match request.epoch() {
            Some(epoch) if epoch != self.epoch() => {
                monitor!(
                    "process_different_epoch_rpc_request",
                    self.process_different_epoch(epoch, peer_id)
                )?;
                return Ok(());
            },
            None => {
                // TODO: @bchocho @hariria can change after all nodes upgrade to release with enum BlockRetrievalRequest (not struct)
                ensure!(matches!(
                    request,
                    IncomingRpcRequest::DeprecatedBlockRetrieval(_)
                        | IncomingRpcRequest::BlockRetrieval(_)
                ));
            },
            _ => {},
        }

        match request {
            // TODO @bchocho @hariria can remove after all nodes upgrade to release with enum BlockRetrievalRequest (not struct)
            IncomingRpcRequest::DeprecatedBlockRetrieval(
                DeprecatedIncomingBlockRetrievalRequest {
                    req,
                    protocol,
                    response_sender,
                },
            ) => {
                if let Some(tx) = &self.block_retrieval_tx {
                    let incoming_block_retrieval_request = IncomingBlockRetrievalRequest {
                        req: BlockRetrievalRequest::V1(req),
                        protocol,
                        response_sender,
                    };
                    tx.push(peer_id, incoming_block_retrieval_request)
                } else {
                    error!("Round manager not started (in IncomingRpcRequest::DeprecatedBlockRetrieval)");
                    Ok(())
                }
            },
            IncomingRpcRequest::BatchRetrieval(request) => {
                if let Some(tx) = &self.batch_retrieval_tx {
                    tx.push(peer_id, request)
                } else {
                    Err(anyhow::anyhow!("Quorum store not started"))
                }
            },
            IncomingRpcRequest::DAGRequest(request) => {
                if let Some(tx) = &self.dag_rpc_tx {
                    tx.push(peer_id, request)
                } else {
                    Err(anyhow::anyhow!("DAG not bootstrapped"))
                }
            },
            IncomingRpcRequest::CommitRequest(request) => {
                self.execution_client.send_commit_msg(peer_id, request)
            },
            IncomingRpcRequest::RandGenRequest(request) => {
                if let Some(tx) = &self.rand_manager_msg_tx {
                    tx.push(peer_id, request)
                } else {
                    bail!("Rand manager not started");
                }
            },
            IncomingRpcRequest::BlockRetrieval(request) => {
                if let Some(tx) = &self.block_retrieval_tx {
                    tx.push(peer_id, request)
                } else {
                    error!("Round manager not started");
                    Ok(())
                }
            },
            IncomingRpcRequest::SecretShareRequest(request) => {
                let Some(tx) = &self.secret_share_manager_tx else {
                    bail!("Secret share manager not started");
                };
                tx.push(peer_id, request)
            },
        }
```
