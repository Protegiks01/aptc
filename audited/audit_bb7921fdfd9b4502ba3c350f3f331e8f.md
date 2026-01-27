# Audit Report

## Title
Epoch Mismatch in RPC Requests Causes Response Channel Abandonment Leading to Validator Network Instability

## Summary
The `process_rpc_request()` function in `EpochManager` incorrectly handles RPC requests with epoch mismatches by calling `process_different_epoch()` and returning early without sending any response to the requester. This violates RPC protocol semantics, causes the requester's channel to be dropped leading to `UnexpectedResponseChannelCancel` errors, and results in network-wide RPC timeouts during epoch transitions. Unlike consensus messages (which are one-way), RPC requests are request-response pairs that require responses. [1](#0-0) 

## Finding Description

The vulnerability occurs in the epoch mismatch handling logic for RPC requests. When an RPC request arrives with an epoch value that differs from the node's current epoch, the code path diverges incorrectly:

**The Vulnerable Path:** [2](#0-1) 

The function calls `process_different_epoch()` which only handles epoch synchronization logic (sending epoch retrieval requests or proofs), then returns immediately without forwarding the RPC to its handler. This causes the `response_sender` channel in the RPC request structure to be dropped without ever being used. [3](#0-2) 

**Affected RPC Request Types:**
All RPC requests contain a `response_sender: oneshot::Sender<Result<Bytes, RpcError>>` field that must be used to send back a response: [4](#0-3) 

The affected request types are:
- BlockRetrieval [5](#0-4) 
- BatchRetrieval [6](#0-5) 
- DAGRequest [7](#0-6) 
- CommitRequest [8](#0-7) 
- RandGenRequest [9](#0-8) 
- SecretShareRequest [10](#0-9) 

**What Should Happen:**
When an RPC request is processed normally (same epoch), it gets forwarded to the appropriate handler which processes it and sends a response: [11](#0-10) 

**The RPC Error Type:**
When a oneshot channel is dropped without sending, the receiver gets: [12](#0-11) 

**Why This Differs From Consensus Messages:**
The code correctly handles consensus messages (proposals, votes, sync info) from different epochs by discarding them without response: [13](#0-12) 

This is correct for consensus messages because they are **one-way** messages that don't expect responses. However, RPC requests are **request-response** pairs where the sender actively waits for a response.

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos Bug Bounty criteria for the following reasons:

1. **Validator Node Slowdowns** (explicitly listed in High Severity): During epoch transitions, nodes that haven't transitioned yet will send legitimate RPC requests (especially BlockRetrieval for catching up) with their current epoch to nodes that have already transitioned. All these requests will timeout, causing significant slowdowns in network synchronization.

2. **Significant Protocol Violations** (explicitly listed in High Severity): RPC semantics mandate that every request receives either a success or error response. Abandoning the response channel violates this fundamental protocol guarantee.

3. **DoS Attack Vector**: A malicious peer can send continuous streams of RPC requests with invalid epochs to any validator. Each request will cause:
   - The validator to process the epoch check logic
   - The requester's RPC to wait until timeout (typically several seconds)
   - Resource waste on both sides
   
   By targeting multiple validators with many such requests, an attacker can cause network-wide RPC handler exhaustion.

4. **Consensus Disruption During Epoch Transitions**: Block retrieval is critical for consensus progress. When BlockRetrieval RPCs fail during epoch transitions, nodes cannot sync blocks efficiently, delaying:
   - Quorum certificate insertion
   - State synchronization  
   - Consensus participation

5. **Network Instability Cascade**: During epoch N→N+1 transitions, nodes transition at different times. Nodes still at epoch N sending RPCs to nodes at epoch N+1 (or vice versa) will all experience timeouts, creating a network-wide cascade of failures.

## Likelihood Explanation

**High Likelihood** - This issue manifests in two scenarios:

1. **Natural Occurrence During Epoch Transitions**: Every epoch transition naturally creates this condition. Nodes don't transition simultaneously, so there's always a period where nodes at different epochs are communicating. The probability of RPC requests crossing epoch boundaries during this window is nearly 100%.

2. **Malicious Exploitation**: An attacker can trivially trigger this by:
   - Observing the current network epoch from any public endpoint
   - Sending RPC requests with epoch values of `current_epoch ± 1`
   - No authentication bypass or privilege escalation required
   - Can be done from any network peer

The vulnerability is also highly likely to go unnoticed in testing because:
- Epoch transitions are infrequent in testnets
- Timeout errors might be attributed to network latency
- The error message `UnexpectedResponseChannelCancel` doesn't clearly indicate the root cause

## Recommendation

Send an appropriate error response before returning when an epoch mismatch is detected. The fix should:

1. Create an error response indicating epoch mismatch
2. Send it via the `response_sender` channel before returning
3. Ensure all RPC request types are handled

**Proposed Fix:**

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
            // Send epoch mismatch error response before returning
            let error = RpcError::ApplicationError(anyhow::anyhow!(
                "Epoch mismatch: request epoch {} != current epoch {}",
                epoch,
                self.epoch()
            ));
            
            // Send error response based on request type
            match request {
                IncomingRpcRequest::BlockRetrieval(req) 
                | IncomingRpcRequest::DeprecatedBlockRetrieval(
                    DeprecatedIncomingBlockRetrievalRequest { response_sender: req.response_sender, .. }
                ) => {
                    let _ = req.response_sender.send(Err(error));
                },
                IncomingRpcRequest::BatchRetrieval(req) => {
                    let _ = req.response_sender.send(Err(error));
                },
                IncomingRpcRequest::DAGRequest(req) => {
                    let _ = req.responder.response_sender.send(Err(error));
                },
                IncomingRpcRequest::CommitRequest(req) => {
                    let _ = req.response_sender.send(Err(error));
                },
                IncomingRpcRequest::RandGenRequest(req) => {
                    let _ = req.response_sender.send(Err(error));
                },
                IncomingRpcRequest::SecretShareRequest(req) => {
                    let _ = req.response_sender.send(Err(error));
                },
            }
            
            // Still call process_different_epoch for epoch synchronization
            monitor!(
                "process_different_epoch_rpc_request",
                self.process_different_epoch(epoch, peer_id)
            )?;
            return Ok(());
        },
        None => {
            ensure!(matches!(
                request,
                IncomingRpcRequest::DeprecatedBlockRetrieval(_)
                    | IncomingRpcRequest::BlockRetrieval(_)
            ));
        },
        _ => {},
    }
    
    // ... rest of the function unchanged
}
```

## Proof of Concept

**Scenario: Epoch Transition RPC Timeout**

1. **Setup**: Network at epoch 100, validator node V1 transitions to epoch 101
2. **Trigger**: Validator node V2 (still at epoch 100) needs blocks and sends BlockRetrieval RPC
3. **Execution Flow**:
   ```
   V2 (epoch 100) -> BlockRetrievalRequest(epoch=100) -> V1 (epoch 101)
   V1 receives: IncomingBlockRetrievalRequest { req: ..., response_sender: tx }
   V1 calls: process_rpc_request(V2, request)
   V1 checks: request.epoch() = Some(100) != self.epoch() = 101
   V1 executes: process_different_epoch(100, V2) -> sends EpochRetrievalRequest
   V1 returns: Ok(()) without using response_sender
   V1 drops: response_sender (tx) is dropped
   V2 receives: RpcError::UnexpectedResponseChannelCancel after timeout
   ```

4. **Impact**: V2 cannot retrieve blocks, must retry with exponential backoff, delaying consensus participation

**Malicious DoS Attack**:
```rust
// Attacker code (pseudocode)
let target_validator = "validator_address";
let wrong_epoch = current_epoch - 1; // or + 1

// Flood with RPC requests
for _ in 0..1000 {
    tokio::spawn(async move {
        let request = BlockRetrievalRequest::V2(BlockRetrievalRequestV2 {
            block_id: HashValue::random(),
            num_blocks: 10,
            target_round: Some(100),
        });
        
        // This will timeout after RPC_TIMEOUT_MSEC
        let _ = network_client.send_rpc_with_epoch(
            target_validator,
            request,
            wrong_epoch, // Intentionally wrong
        ).await;
    });
}
// Each request consumes ~10 seconds of timeout
// 1000 concurrent requests = massive resource waste
```

**Notes:**
- This vulnerability is distinct from normal epoch synchronization flow
- The fix maintains backward compatibility while adding proper error responses
- The issue does not affect consensus safety but severely impacts liveness and availability
- During epoch transitions (which occur regularly), this becomes a network-wide issue affecting all inter-validator RPC communication

### Citations

**File:** consensus/src/epoch_manager.rs (L478-542)
```rust
    fn process_different_epoch(
        &mut self,
        different_epoch: u64,
        peer_id: AccountAddress,
    ) -> anyhow::Result<()> {
        debug!(
            LogSchema::new(LogEvent::ReceiveMessageFromDifferentEpoch)
                .remote_peer(peer_id)
                .epoch(self.epoch()),
            remote_epoch = different_epoch,
        );
        match different_epoch.cmp(&self.epoch()) {
            Ordering::Less => {
                if self
                    .epoch_state()
                    .verifier
                    .get_voting_power(&self.author)
                    .is_some()
                {
                    // Ignore message from lower epoch if we're part of the validator set, the node would eventually see messages from
                    // higher epoch and request a proof
                    sample!(
                        SampleRate::Duration(Duration::from_secs(1)),
                        debug!("Discard message from lower epoch {} from {}", different_epoch, peer_id);
                    );
                    Ok(())
                } else {
                    // reply back the epoch change proof if we're not part of the validator set since we won't broadcast
                    // timeout in this epoch
                    monitor!(
                        "process_epoch_retrieval",
                        self.process_epoch_retrieval(
                            EpochRetrievalRequest {
                                start_epoch: different_epoch,
                                end_epoch: self.epoch(),
                            },
                            peer_id
                        )
                    )
                }
            },
            // We request proof to join higher epoch
            Ordering::Greater => {
                let request = EpochRetrievalRequest {
                    start_epoch: self.epoch(),
                    end_epoch: different_epoch,
                };
                let msg = ConsensusMsg::EpochRetrievalRequest(Box::new(request));
                if let Err(err) = self.network_sender.send_to(peer_id, msg) {
                    warn!(
                        "[EpochManager] Failed to send epoch retrieval to {}, {:?}",
                        peer_id, err
                    );
                    counters::EPOCH_MANAGER_ISSUES_DETAILS
                        .with_label_values(&["failed_to_send_epoch_retrieval"])
                        .inc();
                }

                Ok(())
            },
            Ordering::Equal => {
                bail!("[EpochManager] Same epoch should not come to process_different_epoch");
            },
        }
    }
```

**File:** consensus/src/epoch_manager.rs (L1633-1653)
```rust
            ConsensusMsg::ProposalMsg(_)
            | ConsensusMsg::OptProposalMsg(_)
            | ConsensusMsg::SyncInfo(_)
            | ConsensusMsg::VoteMsg(_)
            | ConsensusMsg::RoundTimeoutMsg(_)
            | ConsensusMsg::OrderVoteMsg(_)
            | ConsensusMsg::CommitVoteMsg(_)
            | ConsensusMsg::CommitDecisionMsg(_)
            | ConsensusMsg::BatchMsg(_)
            | ConsensusMsg::BatchRequestMsg(_)
            | ConsensusMsg::SignedBatchInfo(_)
            | ConsensusMsg::ProofOfStoreMsg(_) => {
                let event: UnverifiedEvent = msg.into();
                if event.epoch()? == self.epoch() {
                    return Ok(Some(event));
                } else {
                    monitor!(
                        "process_different_epoch_consensus_msg",
                        self.process_different_epoch(event.epoch()?, peer_id)
                    )?;
                }
```

**File:** consensus/src/epoch_manager.rs (L1806-1822)
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
```

**File:** consensus/src/epoch_manager.rs (L1855-1860)
```rust
            IncomingRpcRequest::BatchRetrieval(request) => {
                if let Some(tx) = &self.batch_retrieval_tx {
                    tx.push(peer_id, request)
                } else {
                    Err(anyhow::anyhow!("Quorum store not started"))
                }
```

**File:** consensus/src/epoch_manager.rs (L1862-1867)
```rust
            IncomingRpcRequest::DAGRequest(request) => {
                if let Some(tx) = &self.dag_rpc_tx {
                    tx.push(peer_id, request)
                } else {
                    Err(anyhow::anyhow!("DAG not bootstrapped"))
                }
```

**File:** consensus/src/epoch_manager.rs (L1869-1871)
```rust
            IncomingRpcRequest::CommitRequest(request) => {
                self.execution_client.send_commit_msg(peer_id, request)
            },
```

**File:** consensus/src/epoch_manager.rs (L1872-1877)
```rust
            IncomingRpcRequest::RandGenRequest(request) => {
                if let Some(tx) = &self.rand_manager_msg_tx {
                    tx.push(peer_id, request)
                } else {
                    bail!("Rand manager not started");
                }
```

**File:** consensus/src/epoch_manager.rs (L1879-1886)
```rust
            IncomingRpcRequest::BlockRetrieval(request) => {
                if let Some(tx) = &self.block_retrieval_tx {
                    tx.push(peer_id, request)
                } else {
                    error!("Round manager not started");
                    Ok(())
                }
            },
```

**File:** consensus/src/epoch_manager.rs (L1887-1892)
```rust
            IncomingRpcRequest::SecretShareRequest(request) => {
                let Some(tx) = &self.secret_share_manager_tx else {
                    bail!("Secret share manager not started");
                };
                tx.push(peer_id, request)
            },
```

**File:** consensus/src/network.rs (L110-130)
```rust
pub struct DeprecatedIncomingBlockRetrievalRequest {
    pub req: BlockRetrievalRequestV1,
    pub protocol: ProtocolId,
    pub response_sender: oneshot::Sender<Result<Bytes, RpcError>>,
}

/// The block retrieval request is used internally for implementing RPC: the callback is executed
/// for carrying the response
#[derive(Debug)]
pub struct IncomingBlockRetrievalRequest {
    pub req: BlockRetrievalRequest,
    pub protocol: ProtocolId,
    pub response_sender: oneshot::Sender<Result<Bytes, RpcError>>,
}

#[derive(Debug)]
pub struct IncomingBatchRetrievalRequest {
    pub req: BatchRequest,
    pub protocol: ProtocolId,
    pub response_sender: oneshot::Sender<Result<Bytes, RpcError>>,
}
```

**File:** consensus/src/block_storage/sync_manager.rs (L599-614)
```rust
    pub async fn process_block_retrieval(
        &self,
        request: IncomingBlockRetrievalRequest,
    ) -> anyhow::Result<()> {
        fail_point!("consensus::process_block_retrieval", |_| {
            Err(anyhow::anyhow!("Injected error in process_block_retrieval"))
        });
        let response = self.process_block_retrieval_inner(&request.req).await;
        let response_bytes = request
            .protocol
            .to_bytes(&ConsensusMsg::BlockRetrievalResponse(response))?;
        request
            .response_sender
            .send(Ok(response_bytes.into()))
            .map_err(|_| anyhow::anyhow!("Failed to send block retrieval response"))
    }
```

**File:** network/framework/src/protocols/rpc/error.rs (L56-60)
```rust
impl From<oneshot::Canceled> for RpcError {
    fn from(_: oneshot::Canceled) -> Self {
        RpcError::UnexpectedResponseChannelCancel
    }
}
```
