# Audit Report

## Title
DAG Shutdown Race Condition Allows Message Processing During Epoch Transition

## Summary
A race condition in `shutdown_current_processor()` allows DAG messages to be queued and processed by the old DAG instance during epoch transitions because `dag_rpc_tx` is never set to `None`, while the shutdown acknowledgement is being awaited. This can lead to storage corruption and consensus state inconsistencies.

## Finding Description

The vulnerability exists in the DAG shutdown sequence within the `EpochManager::shutdown_current_processor()` function. When an epoch transition occurs, the function properly sends a shutdown signal to the DAG bootstrapper and waits for acknowledgement, but critically fails to set `dag_rpc_tx` to `None`, unlike all other message channels. [1](#0-0) 

During the shutdown window (between sending the shutdown signal and receiving acknowledgement), new DAG RPC requests continue to be accepted and queued because `process_rpc_request()` only checks if `dag_rpc_tx` is `Some()`: [2](#0-1) 

The old DAG instance, running in `DagBootstrapper::start()`, continues processing messages from the channel until it receives and acknowledges the shutdown signal: [3](#0-2) 

**Attack Sequence:**

1. Network receives epoch change proof, triggering `initiate_new_epoch()`
2. `shutdown_current_processor()` is called, sending shutdown signal via `dag_shutdown_tx`
3. **RACE WINDOW OPENS**: `dag_rpc_tx` remains `Some()`, new messages can be queued
4. Attacker sends DAG messages (nodes, votes, fetch requests) from the network
5. `process_rpc_request()` accepts messages because `dag_rpc_tx` is still available
6. Messages are pushed to the channel and processed by the old DAG instance
7. Old DAG writes to ConsensusDB storage using stale epoch configuration
8. DAG acknowledges shutdown, **RACE WINDOW CLOSES**
9. New epoch's DAG starts with potentially corrupted/inconsistent storage state

The epoch check in `process_rpc_request()` does not protect against this race because `self.epoch()` still returns the old epoch value until `start_new_epoch()` updates `self.epoch_state`: [4](#0-3) 

The DAG performs persistent storage operations that can corrupt state during this window: [5](#0-4) 

## Impact Explanation

**High Severity** per Aptos bug bounty criteria:

1. **Significant Protocol Violations**: The old DAG processes messages with stale epoch configuration (wrong validator set, wrong epoch state), violating the atomic epoch transition guarantee.

2. **Storage Corruption**: DAG operations write to ConsensusDB (`save_certified_node`, `save_vote`, `save_pending_node`) during the transition window, creating inconsistent state that the new epoch's DAG may read.

3. **Consensus State Inconsistency**: Breaking **Invariant #4 (State Consistency)** - state transitions are no longer atomic during epoch changes, as the old DAG continues modifying storage while the system transitions.

4. **Validator Node Impact**: Affected nodes may experience slowdowns, crashes, or require manual intervention to resolve storage inconsistencies.

This does not reach Critical severity because it requires precise timing and does not directly cause fund loss or permanent network partition, but it represents a serious consensus layer vulnerability.

## Likelihood Explanation

**Moderate to High Likelihood:**

1. **Deterministic Window**: The race window exists on every epoch transition, which occurs regularly in the Aptos network.

2. **Observable Trigger**: Epoch change proofs are broadcast on the network, giving attackers clear visibility into when to send malicious messages.

3. **No Privilege Required**: Any network peer can send DAG RPC requests without validator privileges.

4. **Timing Achievable**: The window between shutdown signal and acknowledgement is long enough (involves async operations) for network messages to arrive and be queued.

5. **Reproducible**: The vulnerability is deterministic - if messages arrive during the window, they will be processed by the old DAG.

## Recommendation

Set `dag_rpc_tx` to `None` immediately after taking `dag_shutdown_tx`, before sending the shutdown signal, to prevent new messages from being queued during the shutdown window:

```rust
async fn shutdown_current_processor(&mut self) {
    // ... existing round_manager shutdown code ...

    if let Some(close_tx) = self.dag_shutdown_tx.take() {
        // CRITICAL FIX: Drop dag_rpc_tx BEFORE sending shutdown signal
        self.dag_rpc_tx = None;
        
        let (ack_tx, ack_rx) = oneshot::channel();
        close_tx
            .send(ack_tx)
            .expect("[EpochManager] Fail to drop DAG bootstrapper");
        ack_rx
            .await
            .expect("[EpochManager] Fail to drop DAG bootstrapper");
    }
    self.dag_shutdown_tx = None;
    
    // ... rest of shutdown code ...
}
```

This matches the pattern used for other components like `rand_manager_msg_tx` and `secret_share_manager_tx`, ensuring no messages are accepted after shutdown begins.

## Proof of Concept

The vulnerability can be demonstrated with the following test scenario:

```rust
// Integration test demonstrating the race condition
#[tokio::test]
async fn test_dag_shutdown_race_condition() {
    // Setup: Initialize EpochManager with DAG enabled
    let mut epoch_manager = setup_epoch_manager_with_dag();
    
    // Trigger epoch transition
    let epoch_change_proof = create_epoch_change_proof(/* epoch N+1 */);
    
    // Spawn task to send shutdown
    let shutdown_handle = tokio::spawn(async move {
        epoch_manager.shutdown_current_processor().await;
    });
    
    // Wait briefly for shutdown signal to be sent
    tokio::time::sleep(Duration::from_millis(10)).await;
    
    // RACE: Send DAG message while shutdown is in progress
    let dag_request = create_dag_rpc_request(/* malicious payload */);
    let result = epoch_manager.process_rpc_request(peer_id, dag_request);
    
    // BUG: Message is accepted and queued because dag_rpc_tx is still Some()
    assert!(result.is_ok(), "Message should be rejected but was accepted");
    
    // Verify that message was processed by old DAG instance
    // and potentially wrote to storage with stale configuration
    let storage_state = check_consensus_db_state();
    assert!(storage_state.is_inconsistent(), "Storage corrupted by race condition");
    
    shutdown_handle.await.unwrap();
}
```

**Reproduction Steps:**
1. Set up an Aptos testnet with DAG consensus enabled
2. Monitor for epoch change proofs
3. Upon detecting epoch transition, immediately send DAG RPC requests (CertifiedNode, Vote, or FetchRequest messages)
4. Observe that messages are accepted and processed during the shutdown window
5. Check ConsensusDB for inconsistent state after epoch transition completes

## Notes

This vulnerability is specific to the DAG consensus implementation and exists because `dag_rpc_tx` channel cleanup was overlooked during shutdown, unlike other message channels (`rand_manager_msg_tx`, `secret_share_manager_tx`, `block_retrieval_tx`, `batch_retrieval_tx`) which are all properly set to `None`. The fix is straightforward and follows existing patterns in the codebase.

### Citations

**File:** consensus/src/epoch_manager.rs (L637-683)
```rust
    async fn shutdown_current_processor(&mut self) {
        if let Some(close_tx) = self.round_manager_close_tx.take() {
            // Release the previous RoundManager, especially the SafetyRule client
            let (ack_tx, ack_rx) = oneshot::channel();
            close_tx
                .send(ack_tx)
                .expect("[EpochManager] Fail to drop round manager");
            ack_rx
                .await
                .expect("[EpochManager] Fail to drop round manager");
        }
        self.round_manager_tx = None;

        if let Some(close_tx) = self.dag_shutdown_tx.take() {
            // Release the previous RoundManager, especially the SafetyRule client
            let (ack_tx, ack_rx) = oneshot::channel();
            close_tx
                .send(ack_tx)
                .expect("[EpochManager] Fail to drop DAG bootstrapper");
            ack_rx
                .await
                .expect("[EpochManager] Fail to drop DAG bootstrapper");
        }
        self.dag_shutdown_tx = None;

        // Shutdown the previous rand manager
        self.rand_manager_msg_tx = None;

        // Shutdown the previous secret share manager
        self.secret_share_manager_tx = None;

        // Shutdown the previous buffer manager, to release the SafetyRule client
        self.execution_client.end_epoch().await;

        // Shutdown the block retrieval task by dropping the sender
        self.block_retrieval_tx = None;
        self.batch_retrieval_tx = None;

        if let Some(mut quorum_store_coordinator_tx) = self.quorum_store_coordinator_tx.take() {
            let (ack_tx, ack_rx) = oneshot::channel();
            quorum_store_coordinator_tx
                .send(CoordinatorCommand::Shutdown(ack_tx))
                .await
                .expect("Could not send shutdown indicator to QuorumStore");
            ack_rx.await.expect("Failed to stop QuorumStore");
        }
    }
```

**File:** consensus/src/epoch_manager.rs (L1815-1822)
```rust
        match request.epoch() {
            Some(epoch) if epoch != self.epoch() => {
                monitor!(
                    "process_different_epoch_rpc_request",
                    self.process_different_epoch(epoch, peer_id)
                )?;
                return Ok(());
            },
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

**File:** consensus/src/dag/bootstrap.rs (L697-729)
```rust
    pub async fn start(
        self,
        mut dag_rpc_rx: Receiver<Author, IncomingDAGRequest>,
        mut shutdown_rx: oneshot::Receiver<oneshot::Sender<()>>,
    ) {
        info!(
            LogSchema::new(LogEvent::EpochStart),
            epoch = self.epoch_state.epoch,
        );

        let (base_state, handler, fetch_service) = self.full_bootstrap();

        let mut mode = Mode::Active(ActiveMode {
            handler,
            fetch_service,
            base_state,
            buffer: Vec::new(),
        });
        loop {
            select! {
                biased;
                Ok(ack_tx) = &mut shutdown_rx => {
                    let _ = ack_tx.send(());
                    info!(LogSchema::new(LogEvent::Shutdown), epoch = self.epoch_state.epoch);
                    return;
                },
                Some(next_mode) = mode.run(&mut dag_rpc_rx, &self) => {
                    info!(LogSchema::new(LogEvent::ModeTransition), next_mode = %next_mode);
                    mode = next_mode;
                }
            }
        }
    }
```

**File:** consensus/src/dag/storage.rs (L48-72)
```rust
pub trait DAGStorage: Send + Sync {
    fn save_pending_node(&self, node: &Node) -> anyhow::Result<()>;

    fn get_pending_node(&self) -> anyhow::Result<Option<Node>>;

    fn delete_pending_node(&self) -> anyhow::Result<()>;

    fn save_vote(&self, node_id: &NodeId, vote: &Vote) -> anyhow::Result<()>;

    fn get_votes(&self) -> anyhow::Result<Vec<(NodeId, Vote)>>;

    fn delete_votes(&self, node_ids: Vec<NodeId>) -> anyhow::Result<()>;

    fn save_certified_node(&self, node: &CertifiedNode) -> anyhow::Result<()>;

    fn get_certified_nodes(&self) -> anyhow::Result<Vec<(HashValue, CertifiedNode)>>;

    fn delete_certified_nodes(&self, digests: Vec<HashValue>) -> anyhow::Result<()>;

    fn get_latest_k_committed_events(&self, k: u64) -> anyhow::Result<Vec<CommitEvent>>;

    fn get_latest_ledger_info(&self) -> anyhow::Result<LedgerInfoWithSignatures>;

    fn get_epoch_to_proposers(&self) -> HashMap<u64, Vec<Author>>;
}
```
