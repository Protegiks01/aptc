# Audit Report

## Title
RPC Requests With Epoch Mismatch Are Dropped Without Response, Causing Timeout-Based Liveness Degradation

## Summary
The `process_rpc_request()` function in `EpochManager` violates the RPC request-response contract by dropping requests from different epochs without sending error responses back to callers. This causes request timeouts, exponential backoff retry storms, and consensus performance degradation during epoch transitions.

## Finding Description

The consensus epoch manager handles epoch mismatches differently for consensus messages (one-way) versus RPC requests (request-response), creating a protocol violation during epoch transitions.

When an RPC request arrives with an epoch that doesn't match the current epoch, the code detects the mismatch and calls `process_different_epoch()`, then returns early without sending any response. [1](#0-0) 

All affected RPC request types contain `response_sender` fields (oneshot channels) that expect responses:
- `IncomingBatchRetrievalRequest` [2](#0-1) 
- `IncomingDAGRequest` [3](#0-2) 
- `IncomingCommitRequest` [4](#0-3) 
- `IncomingRandGenRequest` [5](#0-4) 
- `IncomingSecretShareRequest` [6](#0-5) 

The `process_different_epoch()` function only handles epoch synchronization logic. When a validator receives a message from a lower epoch, it simply returns `Ok()` without any action, including without sending RPC responses. [7](#0-6) 

**Attack Scenario:**
During epoch transition from N to N+1:
1. Node A (epoch N) sends `RandGenRequest` to Node B (epoch N+1)
2. Node B detects epoch mismatch and calls `process_different_epoch(N, peer_id)`
3. Since N < N+1 and Node B is a validator, it returns `Ok()` discarding the message
4. The function returns early, never reaching the code that forwards to the rand manager [8](#0-7) 
5. Node A's `response_sender` oneshot channel is dropped without sending a response
6. Node A waits for the configured timeout (default 1000ms) [9](#0-8) 
7. ReliableBroadcast retry logic triggers with exponential backoff [10](#0-9) 
8. Retries continue with increasing delays (default: 2ms base × 50 factor, capped at 3000ms) [11](#0-10) 

This affects all epoch-aware RPC requests during transitions, impacting:
- **BatchRetrieval**: QuorumStore batch synchronization
- **DAGRequest**: DAG consensus coordination  
- **CommitRequest**: Commit synchronization
- **RandGenRequest**: Randomness beacon generation
- **SecretShareRequest**: Secret sharing protocol

## Impact Explanation

**Severity: HIGH** (per Aptos bug bounty criteria: "Validator node slowdowns")

This vulnerability causes validator node slowdowns during epoch transitions through:

1. **Critical Consensus Operation Failures**: Randomness generation uses ReliableBroadcast for RPC coordination [12](#0-11) , and when RPCs timeout without responses, the entire randomness protocol stalls until retries succeed.

2. **Network Amplification**: The exponential backoff retry mechanism [13](#0-12)  creates increasing retry traffic during epoch boundaries, wasting network bandwidth and computational resources on doomed requests.

3. **Consensus Performance Degradation**: The inability to complete RPC operations during epoch transitions degrades block proposal coordination, voting, and overall consensus throughput during the critical epoch boundary period.

While this doesn't cause permanent network failure (resolves once epoch transition completes), it creates a significant temporary performance degradation window affecting all validators, matching the HIGH severity "Validator Node Slowdowns" category in the Aptos bug bounty program.

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability triggers deterministically during every epoch transition:
- Epoch changes occur regularly in Aptos at governance-defined intervals
- Nodes don't transition epochs atomically - there's always a time window where different nodes are at different epochs
- No attacker action required - this is a protocol-level bug affecting normal operations
- The vulnerability is guaranteed to occur during every epoch transition, affecting all validators that attempt cross-epoch RPC communication

The RPC requests are sent during normal consensus operations, and the epoch mismatch condition is unavoidable during the transition window.

## Recommendation

Modify `process_rpc_request()` to send error responses for epoch mismatches instead of silently dropping requests:

```rust
match request.epoch() {
    Some(epoch) if epoch != self.epoch() => {
        monitor!(
            "process_different_epoch_rpc_request",
            self.process_different_epoch(epoch, peer_id)
        )?;
        
        // Send error response indicating epoch mismatch
        let error_msg = format!("Epoch mismatch: request epoch {}, current epoch {}", 
                               epoch, self.epoch());
        
        // Send appropriate error response based on request type
        match request {
            IncomingRpcRequest::BatchRetrieval(req) => {
                let _ = req.response_sender.send(Err(RpcError::ApplicationError(
                    Bytes::from(error_msg)
                )));
            },
            IncomingRpcRequest::DAGRequest(req) => {
                let _ = req.responder.response_sender.send(Err(RpcError::ApplicationError(
                    Bytes::from(error_msg)
                )));
            },
            // ... handle other request types similarly
            _ => {},
        }
        
        return Ok(());
    },
    // ... rest of the function
}
```

This allows callers to immediately detect epoch mismatches and handle them appropriately without waiting for timeouts.

## Proof of Concept

The vulnerability can be observed by monitoring RPC timeouts during epoch transitions:

1. Monitor consensus logs during an epoch transition
2. Observe RPC timeout errors for `RandGenRequest`, `BatchRetrieval`, etc.
3. Observe exponential backoff retry patterns in the logs
4. Measure increased network traffic and consensus latency during the epoch boundary window

The specific code paths demonstrating the vulnerability:
- RPC request reception: [14](#0-13) 
- Epoch mismatch handling: [1](#0-0) 
- Response sender dropped without use when early return occurs

## Notes

This is a protocol design flaw rather than a security exploit, but it meets the HIGH severity criteria for "Validator node slowdowns" in the Aptos bug bounty program. The issue affects consensus liveness (performance) during epoch transitions but does not compromise consensus safety or enable fund theft.

### Citations

**File:** consensus/src/epoch_manager.rs (L489-503)
```rust
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
```

**File:** consensus/src/epoch_manager.rs (L1815-1821)
```rust
        match request.epoch() {
            Some(epoch) if epoch != self.epoch() => {
                monitor!(
                    "process_different_epoch_rpc_request",
                    self.process_different_epoch(epoch, peer_id)
                )?;
                return Ok(());
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

**File:** consensus/src/epoch_manager.rs (L1943-1947)
```rust
                (peer, request) = network_receivers.rpc_rx.select_next_some() => {
                    monitor!("epoch_manager_process_rpc",
                    if let Err(e) = self.process_rpc_request(peer, request) {
                        error!(epoch = self.epoch(), error = ?e, kind = error_kind(&e));
                    });
```

**File:** consensus/src/network.rs (L126-130)
```rust
pub struct IncomingBatchRetrievalRequest {
    pub req: BatchRequest,
    pub protocol: ProtocolId,
    pub response_sender: oneshot::Sender<Result<Bytes, RpcError>>,
}
```

**File:** consensus/src/network.rs (L132-137)
```rust
#[derive(Debug)]
pub struct IncomingDAGRequest {
    pub req: DAGNetworkMessage,
    pub sender: Author,
    pub responder: RpcResponder,
}
```

**File:** consensus/src/network.rs (L139-144)
```rust
#[derive(Debug)]
pub struct IncomingCommitRequest {
    pub req: CommitMessage,
    pub protocol: ProtocolId,
    pub response_sender: oneshot::Sender<Result<Bytes, RpcError>>,
}
```

**File:** consensus/src/network.rs (L146-152)
```rust
#[derive(Debug)]
pub struct IncomingRandGenRequest {
    pub req: RandGenMessage,
    pub sender: Author,
    pub protocol: ProtocolId,
    pub response_sender: oneshot::Sender<Result<Bytes, RpcError>>,
}
```

**File:** consensus/src/network.rs (L154-161)
```rust
#[derive(Debug)]
pub struct IncomingSecretShareRequest {
    pub req: SecretShareNetworkMessage,
    #[allow(unused)]
    pub sender: Author,
    pub protocol: ProtocolId,
    pub response_sender: oneshot::Sender<Result<Bytes, RpcError>>,
}
```

**File:** config/src/config/dag_consensus_config.rs (L115-118)
```rust
            // A backoff policy that starts at 100ms and doubles each iteration up to 3secs.
            backoff_policy_base_ms: 2,
            backoff_policy_factor: 50,
            backoff_policy_max_delay_ms: 3000,
```

**File:** config/src/config/dag_consensus_config.rs (L120-120)
```rust
            rpc_timeout_ms: 1000,
```

**File:** crates/reliable-broadcast/src/lib.rs (L191-200)
```rust
                            Err(e) => {
                                log_rpc_failure(e, receiver);

                                let backoff_strategy = backoff_policies
                                    .get_mut(&receiver)
                                    .expect("should be present");
                                let duration = backoff_strategy.next().expect("should produce value");
                                rpc_futures
                                    .push(send_message(receiver, Some(duration)));
                            },
```

**File:** consensus/src/rand/rand_gen/rand_manager.rs (L88-96)
```rust
        let reliable_broadcast = Arc::new(ReliableBroadcast::new(
            author,
            epoch_state.verifier.get_ordered_account_addresses(),
            network_sender.clone(),
            rb_backoff_policy,
            TimeService::real(),
            Duration::from_millis(rb_config.rpc_timeout_ms),
            bounded_executor,
        ));
```
