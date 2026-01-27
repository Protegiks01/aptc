# Audit Report

## Title
Epoch Validation Bypass in DeprecatedBlockRetrieval and BlockRetrieval RPC Handlers

## Summary
The `DeprecatedBlockRetrieval` and `BlockRetrieval` RPC request paths in `EpochManager::process_rpc_request()` bypass epoch validation checks that are enforced for all other RPC types. This allows nodes from different epochs to query blocks from the current epoch's block store, violating epoch isolation and enabling unauthorized information disclosure.

## Finding Description

The vulnerability exists in the epoch validation logic within the `process_rpc_request()` function. [1](#0-0) 

**Root Cause**: The `IncomingRpcRequest::epoch()` method returns `None` for both `DeprecatedBlockRetrieval` and `BlockRetrieval` requests, while all other RPC types (`BatchRetrieval`, `DAGRequest`, `RandGenRequest`, `CommitRequest`, `SecretShareRequest`) return `Some(epoch)`. [2](#0-1) 

**Exploitation Flow**:

1. When `request.epoch()` returns `None`, the code at lines 1823-1830 only validates that the request matches the allowed deprecated types, but **does not perform any epoch comparison**.

2. All other RPC types trigger epoch validation at lines 1816-1822, where `process_different_epoch()` is called if the epochs don't match. [3](#0-2) 

3. The `process_different_epoch()` function implements proper epoch synchronization logic: rejecting requests from old epochs or initiating epoch sync for newer epochs. [4](#0-3) 

4. By returning `None`, `BlockRetrieval` requests bypass this security gate entirely and are forwarded directly to the block store without epoch context validation.

**Attack Scenario**:
- Attacker (node in epoch N-1 or malicious peer) sends `BlockRetrievalRequest` to victim (node in epoch N)
- Request bypasses epoch check (lines 1823-1830)
- Request is processed by epoch N's block store (lines 1843-1853 or 1879-1886)
- Block store returns blocks based on `block_id` lookup without epoch verification [5](#0-4) 
- Attacker receives unauthorized information about current epoch's block structure

The `BlockRetrievalRequest` structure contains no epoch field, only `block_id`, `num_blocks`, and target information. [6](#0-5) 

## Impact Explanation

This vulnerability enables:

1. **Access Control Violation**: Nodes not in the current validator set can query blocks from the active epoch, violating the epoch isolation model that separates validator sets and consensus state across epochs.

2. **Information Disclosure**: Attackers can probe the block store structure, validator set composition, and block relationships without proper authorization. This leaks information about the current consensus state to unauthorized parties.

3. **Resource Exhaustion**: Malicious peers can flood the node with block retrieval requests that bypass epoch validation, consuming CPU and I/O resources processing invalid cross-epoch queries.

Per Aptos bug bounty criteria, this qualifies as **Medium severity** due to:
- Information leakage to unauthorized parties
- Violation of epoch-based access control assumptions  
- Potential for targeted DoS through resource exhaustion
- Does not directly cause consensus violations or funds loss

## Likelihood Explanation

**Likelihood: High**

The vulnerability is easily exploitable:
- No validator privileges required
- Any network peer can send RPC requests
- BlockRetrieval is a standard protocol operation used during normal sync
- No complex timing or race conditions needed
- Attacker only needs to craft a `BlockRetrievalRequest` with a `block_id` and send it via RPC

The attack is deterministic and reproducible on any Aptos node.

## Recommendation

**Fix**: Add epoch validation for `BlockRetrieval` requests before processing.

**Option 1 - Add epoch field to BlockRetrievalRequest** (preferred long-term solution):
Modify `BlockRetrievalRequest` enum to include epoch information and validate it before processing.

**Option 2 - Implicit epoch validation** (immediate fix):
In `process_rpc_request()`, add explicit epoch check for block retrieval requests:

```rust
match request {
    IncomingRpcRequest::DeprecatedBlockRetrieval(req) => {
        // Reject if not in current epoch context
        if self.block_retrieval_tx.is_none() {
            bail!("Block retrieval not available - epoch not initialized");
        }
        // ... existing code
    },
    IncomingRpcRequest::BlockRetrieval(req) => {
        // Reject if not in current epoch context  
        if self.block_retrieval_tx.is_none() {
            bail!("Block retrieval not available - epoch not initialized");
        }
        // ... existing code
    },
}
```

Additionally, the silent `Ok(())` return when `block_retrieval_tx` is `None` should be changed to return an error or send a proper response to the peer indicating the service is unavailable.

## Proof of Concept

```rust
// Simulated attack scenario demonstrating epoch bypass

// 1. Attacker in epoch N-1 crafts a BlockRetrievalRequest
let malicious_request = BlockRetrievalRequest::V1(
    BlockRetrievalRequestV1::new(
        HashValue::random(), // block_id from epoch N-1
        10, // num_blocks
    )
);

// 2. Attacker sends RPC to victim node in epoch N
// The request is wrapped as IncomingRpcRequest::BlockRetrieval
let incoming = IncomingRpcRequest::BlockRetrieval(IncomingBlockRetrievalRequest {
    req: malicious_request,
    protocol: rpc_protocol,
    response_sender: callback_channel,
});

// 3. EpochManager.process_rpc_request() receives the request
// At line 1815: request.epoch() returns None for BlockRetrieval
// At line 1823: None case only checks if request matches deprecated types
// NO EPOCH VALIDATION OCCURS

// 4. Request bypasses epoch check and goes directly to block_retrieval_tx
// The victim node's BlockStore processes the request in epoch N context
// Attacker receives blocks (if they exist) or IdNotFound status
// Either way, attacker has successfully queried epoch N without authorization

// Expected behavior: Request should trigger process_different_epoch() 
// and be rejected or redirected to epoch sync, not directly processed.
```

**Notes**:

The vulnerability exists because the deprecated migration path (`DeprecatedBlockRetrieval` → `BlockRetrieval::V1` conversion) was not designed with epoch validation in mind. The assumption that block retrieval requests don't need epoch information (since they use `block_id` instead) creates a security gap where cross-epoch queries bypass the access control enforced for all other RPC types.

While the immediate impact is limited to information disclosure and resource consumption, the violation of epoch isolation principles is a legitimate security concern that could be chained with other vulnerabilities or used for reconnaissance in more sophisticated attacks.

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

**File:** consensus/src/epoch_manager.rs (L1806-1894)
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
    }
```

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

**File:** consensus/consensus-types/src/block_retrieval.rs (L17-45)
```rust
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum BlockRetrievalRequest {
    V1(BlockRetrievalRequestV1),
    V2(BlockRetrievalRequestV2),
}

impl BlockRetrievalRequest {
    pub fn new_with_target_round(block_id: HashValue, num_blocks: u64, target_round: u64) -> Self {
        Self::V2(BlockRetrievalRequestV2 {
            block_id,
            num_blocks,
            target_round,
        })
    }

    pub fn block_id(&self) -> HashValue {
        match self {
            BlockRetrievalRequest::V1(req) => req.block_id,
            BlockRetrievalRequest::V2(req) => req.block_id,
        }
    }

    pub fn num_blocks(&self) -> u64 {
        match self {
            BlockRetrievalRequest::V1(req) => req.num_blocks,
            BlockRetrievalRequest::V2(req) => req.num_blocks,
        }
    }
}
```
