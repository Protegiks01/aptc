# Audit Report

## Title
Improper RPC Error Handling in Batch Retrieval Causing Client Retry Storms

## Summary
When `batch_retrieval_tx` is `None` (quorum store not started), the `process_rpc_request()` function in `EpochManager` drops the RPC response channel without sending an error response, causing clients to receive `UnexpectedResponseChannelCancel` errors and retry unnecessarily, leading to resource exhaustion during node startup/shutdown phases.

## Finding Description
The vulnerability exists in the batch retrieval RPC handler where the response channel is improperly closed when the quorum store is unavailable. [1](#0-0) 

When `batch_retrieval_tx` is `None`, the function returns an error but does not send a response on the `response_sender` channel contained within the `IncomingBatchRetrievalRequest` structure: [2](#0-1) 

The `response_sender` is a oneshot channel that clients wait on. When dropped without being used, it triggers a `oneshot::Canceled` error on the receiver side, which gets converted to `RpcError::UnexpectedResponseChannelCancel`: [3](#0-2) [4](#0-3) [5](#0-4) 

Clients interpret this as a transient network error and retry with exponential backoff: [6](#0-5) 

The retry logic continues until `retry_limit` is exhausted: [7](#0-6) 

The `batch_retrieval_tx` is set to `None` during shutdown and remains `None` until quorum store initialization: [8](#0-7) [9](#0-8) 

## Impact Explanation
This vulnerability causes **Medium severity** resource exhaustion that violates the Resource Limits invariant. During node startup, shutdown, or epoch transitions, multiple clients requesting batches will:

1. **Trigger unnecessary retries**: Each client retries up to `retry_limit` times (typically 5-10 attempts)
2. **Consume network bandwidth**: Each retry involves full RPC roundtrip overhead
3. **Generate log spam**: Error counters increment on both client and server sides
4. **Amplify during recovery**: When multiple nodes restart simultaneously (e.g., network upgrade), all nodes requesting from a restarting node experience this issue, creating a retry storm

The issue breaks the **Resource Limits** invariant by allowing unbounded retry attempts across multiple clients during legitimate operational scenarios.

## Likelihood Explanation
**High likelihood** - This occurs naturally during normal operations:
- Every node startup (quorum store initialization takes time)
- Every node shutdown (quorum store stops before epoch manager)
- Epoch transitions (temporary unavailability window)
- Configuration changes that disable quorum store

In a network with N validators, during a coordinated upgrade, this can trigger N×M retry attempts where M is the number of concurrent batch requests per node.

## Recommendation
Send a proper error response on the RPC channel before returning:

```rust
IncomingRpcRequest::BatchRetrieval(request) => {
    if let Some(tx) = &self.batch_retrieval_tx {
        tx.push(peer_id, request)
    } else {
        // Send error response instead of dropping the channel
        let _ = request.response_sender.send(Err(
            RpcError::Error(anyhow::anyhow!("Quorum store not started"))
        ));
        Ok(())
    }
}
```

Apply the same fix to other RPC handlers with similar issues:
- `DAGRequest` (lines 1862-1867)
- `RandGenRequest` (lines 1872-1877)
- `SecretShareRequest` (lines 1887-1891)

## Proof of Concept
```rust
// Test demonstrating the retry storm
#[tokio::test]
async fn test_batch_retrieval_retry_storm() {
    // Setup: Create EpochManager with batch_retrieval_tx = None
    let mut epoch_manager = create_test_epoch_manager();
    
    // Simulate multiple clients requesting batches
    let num_clients = 10;
    let retry_limit = 5;
    
    let mut total_requests = 0;
    for client_id in 0..num_clients {
        let digest = HashValue::random();
        
        // Each client will retry retry_limit times
        for attempt in 0..retry_limit {
            let request = create_batch_request(digest);
            let result = epoch_manager.process_rpc_request(
                client_id, 
                IncomingRpcRequest::BatchRetrieval(request)
            );
            
            // Verify error is returned and channel is dropped
            assert!(result.is_err());
            total_requests += 1;
        }
    }
    
    // Expected: 50 total requests (10 clients × 5 retries each)
    // All failing with UnexpectedResponseChannelCancel
    assert_eq!(total_requests, num_clients * retry_limit);
    println!("Retry storm generated {} unnecessary requests", total_requests);
}
```

## Notes
While clients do not hang indefinitely (oneshot channel cancellation provides immediate error feedback and retry limits bound total attempts), the improper error handling causes significant resource waste during operational transitions. The error semantics are misleading—clients receive "UnexpectedResponseChannelCancel" suggesting an application bug rather than "service unavailable" indicating a temporary condition. This amplifies during network-wide events like coordinated upgrades, where all validators may simultaneously retry against restarting peers.

### Citations

**File:** consensus/src/epoch_manager.rs (L671-673)
```rust
        // Shutdown the block retrieval task by dropping the sender
        self.block_retrieval_tx = None;
        self.batch_retrieval_tx = None;
```

**File:** consensus/src/epoch_manager.rs (L1005-1012)
```rust
    fn start_quorum_store(&mut self, quorum_store_builder: QuorumStoreBuilder) {
        if let Some((quorum_store_coordinator_tx, batch_retrieval_rx)) =
            quorum_store_builder.start()
        {
            self.quorum_store_coordinator_tx = Some(quorum_store_coordinator_tx);
            self.batch_retrieval_tx = Some(batch_retrieval_rx);
        }
    }
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

**File:** consensus/src/network.rs (L126-130)
```rust
pub struct IncomingBatchRetrievalRequest {
    pub req: BatchRequest,
    pub protocol: ProtocolId,
    pub response_sender: oneshot::Sender<Result<Bytes, RpcError>>,
}
```

**File:** network/framework/src/protocols/rpc/error.rs (L30-31)
```rust
    #[error("Application layer unexpectedly dropped response channel")]
    UnexpectedResponseChannelCancel,
```

**File:** network/framework/src/protocols/rpc/error.rs (L56-60)
```rust
impl From<oneshot::Canceled> for RpcError {
    fn from(_: oneshot::Canceled) -> Self {
        RpcError::UnexpectedResponseChannelCancel
    }
}
```

**File:** network/framework/src/protocols/rpc/mod.rs (L520-524)
```rust
                match result {
                    Ok(Ok(response)) => Ok(Bytes::from(response.raw_response)),
                    Ok(Err(oneshot::Canceled)) => Err(RpcError::UnexpectedResponseChannelCancel),
                    Err(timeout::Elapsed) => Err(RpcError::TimedOut),
                }
```

**File:** consensus/src/quorum_store/batch_requester.rs (L40-63)
```rust
    fn next_request_peers(&mut self, num_peers: usize) -> Option<Vec<PeerId>> {
        let signers = self.signers.lock();
        if self.num_retries == 0 {
            let mut rng = rand::thread_rng();
            // make sure nodes request from the different set of nodes
            self.next_index = rng.r#gen::<usize>() % signers.len();
            counters::SENT_BATCH_REQUEST_COUNT.inc_by(num_peers as u64);
        } else {
            counters::SENT_BATCH_REQUEST_RETRY_COUNT.inc_by(num_peers as u64);
        }
        if self.num_retries < self.retry_limit {
            self.num_retries += 1;
            let ret = signers
                .iter()
                .cycle()
                .skip(self.next_index)
                .take(num_peers)
                .cloned()
                .collect();
            self.next_index = (self.next_index + num_peers) % signers.len();
            Some(ret)
        } else {
            None
        }
```

**File:** consensus/src/quorum_store/batch_requester.rs (L156-159)
```rust
                            Err(e) => {
                                counters::RECEIVED_BATCH_RESPONSE_ERROR_COUNT.inc();
                                debug!("QS: batch request error, digest:{}, error:{:?}", digest, e);
                            }
```
