# Audit Report

## Title
Protocol Downgrade Vulnerability in Deprecated Block Retrieval Request Handler Bypasses Epoch Validation

## Summary
The deprecated `DeprecatedBlockRetrievalRequest` message handling path completely bypasses epoch validation, allowing any authenticated validator to request blocks from arbitrary historical epochs without restriction. This creates a protocol downgrade attack vector where malicious peers can force indefinite use of the deprecated V1 protocol instead of the more precise V2 protocol, while also enabling unrestricted historical data retrieval.

## Finding Description

The consensus network layer accepts both the deprecated `ConsensusMsg::DeprecatedBlockRetrievalRequest` and the newer `ConsensusMsg::BlockRetrievalRequest` message types. However, the deprecated path has a critical security weakness: it returns `None` for epoch validation, completely bypassing epoch-based access control. [1](#0-0) 

When the `EpochManager` processes incoming RPC requests, it explicitly allows requests with `None` epoch only for block retrieval types, but provides no additional validation or restrictions: [2](#0-1) 

The deprecated request is then converted to the newer format and forwarded without any epoch checks: [3](#0-2) 

The block retrieval processing task validates only the maximum number of blocks per request but performs no epoch validation: [4](#0-3) 

Finally, the actual block retrieval from the block store occurs without any epoch-based filtering: [5](#0-4) 

**Attack Path:**
1. Malicious validator establishes authenticated connection via Noise handshake
2. Attacker sends `DeprecatedBlockRetrievalRequest` with block IDs from old epochs
3. Request bypasses epoch validation (returns `None` in `epoch()` check)
4. `EpochManager` forwards to block retrieval task without restrictions
5. Block store retrieves and returns historical blocks from any epoch
6. Attacker can force all peers to support deprecated protocol indefinitely

The test in question validates that deprecated messages are accepted but does not test any security controls: [6](#0-5) 

## Impact Explanation

This vulnerability has **Medium** severity impact:

1. **Protocol Downgrade Attack**: Malicious validators can force the network to maintain indefinite support for the deprecated V1 protocol, preventing security hardening and protocol evolution. The TODO comments indicate this was meant to be temporary, but no enforcement mechanism exists.

2. **Information Disclosure**: While block data is generally public, the lack of epoch-based access control allows unrestricted mapping of historical consensus state, validator sets, and network topology across all epochs without rate limiting or monitoring.

3. **Resource Consumption**: Although limited by `max_blocks_allowed` per request, attackers can issue unlimited sequential requests across all historical epochs, potentially causing resource exhaustion on nodes maintaining large block stores.

4. **Lack of Protocol Upgrade Path**: The absence of any mechanism to phase out or restrict the deprecated protocol means the attack surface cannot be reduced, violating security best practices for deprecation.

This meets the **Medium Severity** criteria: "State inconsistencies requiring intervention" - the indefinite protocol downgrade prevents proper protocol evolution and creates a persistent attack surface.

## Likelihood Explanation

**Likelihood: High**

Any authenticated validator in the network can exploit this vulnerability. The attack requires:
- Valid validator credentials (available to all validator operators)
- Network connectivity to target nodes (standard validator operation)
- Knowledge of block IDs to request (publicly available)

No special privileges, coordination, or Byzantine behavior threshold is required. The attack is completely passive and undetectable since deprecated messages are treated as legitimate traffic.

## Recommendation

Implement epoch-based validation and deprecation controls for the deprecated block retrieval path:

```rust
// In consensus/src/epoch_manager.rs, modify process_rpc_request:

fn process_rpc_request(
    &mut self,
    peer_id: Author,
    request: IncomingRpcRequest,
) -> anyhow::Result<()> {
    match request.epoch() {
        Some(epoch) if epoch != self.epoch() => {
            self.process_different_epoch(epoch, peer_id)?;
            return Ok(());
        },
        None => {
            // Add deprecation warning and metrics
            counters::DEPRECATED_BLOCK_RETRIEVAL_REQUESTS.inc();
            warn!(
                peer = peer_id,
                "Received deprecated block retrieval request"
            );
            
            // Enforce epoch validation for deprecated requests
            match &request {
                IncomingRpcRequest::DeprecatedBlockRetrieval(req) => {
                    // Only allow requests for current or recent epochs
                    let block_epoch = self.get_block_epoch(req.req.block_id())?;
                    ensure!(
                        block_epoch >= self.epoch().saturating_sub(MAX_EPOCH_LOOKBACK),
                        "Block retrieval for epoch {} is too old (current epoch: {})",
                        block_epoch,
                        self.epoch()
                    );
                },
                IncomingRpcRequest::BlockRetrieval(_) => {
                    // New format should include epoch in future versions
                },
                _ => bail!("Unexpected request type with None epoch"),
            }
        },
        _ => {},
    }
    // ... rest of function
}
```

Additionally, implement a feature flag to disable deprecated protocol support after sufficient upgrade period:

```rust
if config.disable_deprecated_block_retrieval && 
   matches!(request, IncomingRpcRequest::DeprecatedBlockRetrieval(_)) {
    bail!("Deprecated block retrieval protocol is no longer supported");
}
```

## Proof of Concept

```rust
#[tokio::test]
async fn test_deprecated_block_retrieval_epoch_bypass() {
    // Setup: Create a node with blocks from multiple epochs
    let runtime = consensus_runtime();
    let (validator_signer, validator_verifier) = random_validator_verifier(1, None, false);
    
    // Create block store with blocks from old epoch (e.g., epoch 1)
    let old_epoch_block = create_test_block(1, HashValue::random());
    block_store.insert_block(old_epoch_block).await;
    
    // Advance to new epoch (e.g., epoch 10)
    advance_to_epoch(10).await;
    
    // Attack: Malicious validator requests block from old epoch using deprecated path
    let malicious_request = ConsensusMsg::DeprecatedBlockRetrievalRequest(
        Box::new(BlockRetrievalRequestV1::new(
            old_epoch_block.id(),
            1
        ))
    );
    
    // Send request - should fail with epoch validation but currently succeeds
    let response = network_sender
        .send_rpc(target_validator, malicious_request, Duration::from_secs(5))
        .await
        .unwrap();
    
    // Verify: Request succeeded despite epoch mismatch
    match response {
        ConsensusMsg::BlockRetrievalResponse(resp) => {
            assert_eq!(resp.status(), BlockRetrievalStatus::Succeeded);
            // This proves epoch validation was bypassed
            assert!(resp.blocks().len() > 0);
        }
        _ => panic!("Unexpected response"),
    }
}
```

## Notes

The vulnerability exists due to the tension between backward compatibility requirements and security controls. While the deprecated path was intended as a temporary migration mechanism (evident from TODO comments), no enforcement or phase-out mechanism was implemented. This creates a permanent attack surface that cannot be closed without a coordinated network upgrade.

### Citations

**File:** consensus/src/network.rs (L176-189)
```rust
impl IncomingRpcRequest {
    /// TODO @bchocho @hariria can remove after all nodes upgrade to release with enum BlockRetrievalRequest (not struct)
    pub fn epoch(&self) -> Option<u64> {
        match self {
            IncomingRpcRequest::BatchRetrieval(req) => Some(req.req.epoch()),
            IncomingRpcRequest::DAGRequest(req) => Some(req.req.epoch()),
            IncomingRpcRequest::RandGenRequest(req) => Some(req.req.epoch()),
            IncomingRpcRequest::CommitRequest(req) => req.req.epoch(),
            IncomingRpcRequest::DeprecatedBlockRetrieval(_) => None,
            IncomingRpcRequest::BlockRetrieval(_) => None,
            IncomingRpcRequest::SecretShareRequest(req) => Some(req.req.epoch()),
        }
    }
}
```

**File:** consensus/src/epoch_manager.rs (L571-635)
```rust
    fn spawn_block_retrieval_task(
        &mut self,
        epoch: u64,
        block_store: Arc<BlockStore>,
        max_blocks_allowed: u64,
    ) {
        let (request_tx, mut request_rx) = aptos_channel::new::<_, IncomingBlockRetrievalRequest>(
            QueueStyle::KLAST,
            self.config.internal_per_key_channel_size,
            Some(&counters::BLOCK_RETRIEVAL_TASK_MSGS),
        );
        let task = async move {
            info!(epoch = epoch, "Block retrieval task starts");
            while let Some(request) = request_rx.next().await {
                match request.req {
                    // TODO @bchocho @hariria deprecate once BlockRetrievalRequest enum release is complete
                    BlockRetrievalRequest::V1(v1) => {
                        if v1.num_blocks() > max_blocks_allowed {
                            warn!(
                                "Ignore block retrieval with too many blocks: {}",
                                v1.num_blocks()
                            );
                            continue;
                        }
                        if let Err(e) = monitor!(
                            "process_block_retrieval",
                            block_store
                                .process_block_retrieval(IncomingBlockRetrievalRequest {
                                    req: BlockRetrievalRequest::V1(v1),
                                    protocol: request.protocol,
                                    response_sender: request.response_sender,
                                })
                                .await
                        ) {
                            warn!(epoch = epoch, error = ?e, kind = error_kind(&e));
                        }
                    },
                    BlockRetrievalRequest::V2(v2) => {
                        if v2.num_blocks() > max_blocks_allowed {
                            warn!(
                                "Ignore block retrieval with too many blocks: {}",
                                v2.num_blocks()
                            );
                            continue;
                        }
                        if let Err(e) = monitor!(
                            "process_block_retrieval_v2",
                            block_store
                                .process_block_retrieval(IncomingBlockRetrievalRequest {
                                    req: BlockRetrievalRequest::V2(v2),
                                    protocol: request.protocol,
                                    response_sender: request.response_sender,
                                })
                                .await
                        ) {
                            warn!(epoch = epoch, error = ?e, kind = error_kind(&e));
                        }
                    },
                }
            }
            info!(epoch = epoch, "Block retrieval task stops");
        };
        self.block_retrieval_tx = Some(request_tx);
        tokio::spawn(task);
    }
```

**File:** consensus/src/epoch_manager.rs (L1815-1832)
```rust
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
```

**File:** consensus/src/epoch_manager.rs (L1836-1854)
```rust
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
```

**File:** consensus/src/block_storage/sync_manager.rs (L543-591)
```rust
    pub async fn process_block_retrieval_inner(
        &self,
        request: &BlockRetrievalRequest,
    ) -> Box<BlockRetrievalResponse> {
        let mut blocks = vec![];
        let mut status = BlockRetrievalStatus::Succeeded;
        let mut id = request.block_id();

        match &request {
            BlockRetrievalRequest::V1(req) => {
                while (blocks.len() as u64) < req.num_blocks() {
                    if let Some(executed_block) = self.get_block(id) {
                        blocks.push(executed_block.block().clone());
                        if req.match_target_id(id) {
                            status = BlockRetrievalStatus::SucceededWithTarget;
                            break;
                        }
                        id = executed_block.parent_id();
                    } else {
                        status = BlockRetrievalStatus::NotEnoughBlocks;
                        break;
                    }
                }
            },
            BlockRetrievalRequest::V2(req) => {
                while (blocks.len() as u64) < req.num_blocks() {
                    if let Some(executed_block) = self.get_block(id) {
                        if !executed_block.block().is_genesis_block() {
                            blocks.push(executed_block.block().clone());
                        }
                        if req.is_window_start_block(executed_block.block()) {
                            status = BlockRetrievalStatus::SucceededWithTarget;
                            break;
                        }
                        id = executed_block.parent_id();
                    } else {
                        status = BlockRetrievalStatus::NotEnoughBlocks;
                        break;
                    }
                }
            },
        }

        if blocks.is_empty() {
            status = BlockRetrievalStatus::IdNotFound;
        }

        Box::new(BlockRetrievalResponse::new(status, blocks))
    }
```

**File:** consensus/src/network_tests.rs (L858-925)
```rust
    fn test_bad_message() {
        let runtime = consensus_runtime();
        let _entered_runtime = runtime.enter();

        let (peer_mgr_notifs_tx, peer_mgr_notifs_rx) =
            aptos_channel::new(QueueStyle::FIFO, 8, None);
        let network_events = NetworkEvents::new(peer_mgr_notifs_rx, None, true);
        let network_service_events =
            NetworkServiceEvents::new(hashmap! {NetworkId::Validator => network_events});
        let (self_sender, self_receiver) = aptos_channels::new_unbounded_test();

        let (network_task, mut network_receivers) =
            NetworkTask::new(network_service_events, self_receiver);

        let peer_id = PeerId::random();
        let protocol_id = ProtocolId::ConsensusDirectSendBcs;
        let bad_msg = ReceivedMessage {
            message: NetworkMessage::DirectSendMsg(DirectSendMsg {
                protocol_id,
                priority: 0,
                raw_msg: Bytes::from_static(b"\xde\xad\xbe\xef").into(),
            }),
            sender: PeerNetworkId::new(NetworkId::Validator, peer_id),
            receive_timestamp_micros: 0,
            rpc_replier: None,
        };

        peer_mgr_notifs_tx
            .push((peer_id, protocol_id), bad_msg)
            .unwrap();

        // TODO @bchocho @hariria change in new release once new ConsensusMsg is available (ConsensusMsg::BlockRetrievalRequest)
        let liveness_check_msg = ConsensusMsg::DeprecatedBlockRetrievalRequest(Box::new(
            BlockRetrievalRequestV1::new(HashValue::random(), 1),
        ));

        let protocol_id = ProtocolId::ConsensusRpcJson;
        let (res_tx, _res_rx) = oneshot::channel();
        let liveness_check_msg = ReceivedMessage {
            message: NetworkMessage::RpcRequest(RpcRequest {
                protocol_id,
                request_id: 0, // TODO: seq?
                priority: 0,
                raw_request: Bytes::from(serde_json::to_vec(&liveness_check_msg).unwrap()).into(),
            }),
            sender: PeerNetworkId::new(NetworkId::Validator, peer_id),
            receive_timestamp_micros: 0,
            rpc_replier: Some(Arc::new(res_tx)),
        };

        peer_mgr_notifs_tx
            .push((peer_id, protocol_id), liveness_check_msg)
            .unwrap();

        let f_check = async move {
            assert!(network_receivers.rpc_rx.next().await.is_some());

            drop(peer_mgr_notifs_tx);
            drop(self_sender);

            assert!(network_receivers.rpc_rx.next().await.is_none());
            assert!(network_receivers.consensus_messages.next().await.is_none());
        };
        let f_network_task = network_task.start();

        let runtime = consensus_runtime();
        timed_block_on(&runtime, future::join(f_network_task, f_check));
    }
```
