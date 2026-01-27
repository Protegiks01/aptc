# Audit Report

## Title
BoundedExecutor Clone Semantics Enable Cross-Component Resource Exhaustion Leading to Consensus Liveness Failure

## Summary
The `BoundedExecutor` implements `Clone` via `#[derive(Clone)]`, causing all cloned instances to share the same underlying `Arc<Semaphore>` capacity pool. Multiple critical consensus components (RandManager, SecretShareManager, DAG NetworkHandler, and ReliableBroadcast) unintentionally share a single executor with only 16 permits (default configuration), enabling attackers to exhaust the capacity pool by flooding one component and starving others, resulting in validator liveness failure.

## Finding Description

The `BoundedExecutor` struct uses derived `Clone` implementation, which clones the `Arc<Semaphore>` field by incrementing its reference count rather than creating a new semaphore: [1](#0-0) 

In the consensus initialization flow, a single `BoundedExecutor` is created with capacity from configuration (default 16 tasks): [2](#0-1) 

This executor is then cloned and distributed to multiple independent consensus components: [3](#0-2) [4](#0-3) 

The `ExecutionProxyClient` further clones and distributes the executor to `RandManager` and `SecretShareManager`: [5](#0-4) [6](#0-5) 

The `EpochManager` also clones the executor for the DAG bootstrapper: [7](#0-6) 

These components use the shared executor to spawn verification and processing tasks:

**RandManager verification tasks:** [8](#0-7) 

**SecretShareManager verification tasks:** [9](#0-8) 

**DAG NetworkHandler message verification:** [10](#0-9) 

**ReliableBroadcast aggregation tasks:** [11](#0-10) 

The default capacity is only 16 concurrent tasks: [12](#0-11) 

**Attack Path:**
1. Attacker identifies a validator node and floods it with malicious RandGen RPC messages
2. Each message triggers a verification task in `RandManager.verification_task()`
3. These tasks spawn on the shared `BoundedExecutor`, consuming permits
4. With only 16 permits shared across all consensus components, the pool quickly exhausts
5. Critical operations in SecretShareManager, DAG NetworkHandler, and ReliableBroadcast block waiting for permits
6. The validator cannot process DAG messages, complete randomness generation, or perform secret sharing
7. Consensus operations stall, causing the validator to fall behind and lose liveness

This breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits." The unintended capacity sharing allows one component's resource consumption to starve others.

## Impact Explanation

This vulnerability qualifies as **High Severity** under Aptos bug bounty criteria because it causes:

1. **Validator node slowdowns**: The affected validator experiences significant performance degradation as critical consensus tasks are starved of execution capacity
2. **Significant protocol violations**: The validator fails to participate in randomness generation, secret sharing, and DAG consensus, violating protocol requirements

The impact includes:
- **Single validator**: Loss of consensus liveness, missed block proposals, reduced rewards
- **Multiple validators**: If multiple validators are attacked simultaneously, could degrade network throughput and liveness
- **Validator reputation**: Affected validators accumulate failed rounds, damaging their leader reputation

While this doesn't directly cause fund loss or consensus safety violations, it significantly impairs validator operations and network health, meeting the High Severity threshold of "Validator node slowdowns" and "Significant protocol violations."

## Likelihood Explanation

**Likelihood: High**

The attack is straightforward to execute:
- **No privileged access required**: Any network peer can send RPC messages to validator nodes
- **Low attack complexity**: Simply flood the target with malicious RandGen or SecretShare messages
- **Small attack surface**: Only 16 permits to exhaust with default configuration
- **Predictable behavior**: Verification tasks are spawned synchronously for each incoming message
- **No special resources needed**: Standard network connection and message serialization

The vulnerability is likely to be discovered and exploited because:
1. The shared capacity pool is very small (16 permits)
2. Multiple high-volume components compete for the same pool
3. Malicious RPC messages are easy to craft and send
4. The impact is immediate and observable (validator falls behind)

## Recommendation

**Short-term fix**: Allocate separate `BoundedExecutor` instances for each major consensus component to prevent cross-component resource starvation:

```rust
// In consensus_provider.rs
pub fn start_consensus(...) -> ... {
    // Separate executors for different components
    let rand_executor = BoundedExecutor::new(
        node_config.consensus.num_rand_executor_tasks as usize,
        runtime.handle().clone(),
    );
    
    let secret_share_executor = BoundedExecutor::new(
        node_config.consensus.num_secret_share_executor_tasks as usize,
        runtime.handle().clone(),
    );
    
    let dag_executor = BoundedExecutor::new(
        node_config.consensus.num_dag_executor_tasks as usize,
        runtime.handle().clone(),
    );
    
    let general_executor = BoundedExecutor::new(
        node_config.consensus.num_bounded_executor_tasks as usize,
        runtime.handle().clone(),
    );
    
    // Pass appropriate executors to each component
    let execution_client = Arc::new(ExecutionProxyClient::new(
        node_config.consensus.clone(),
        Arc::new(execution_proxy),
        node_config.validator_network.as_ref().unwrap().peer_id(),
        self_sender.clone(),
        consensus_network_client.clone(),
        rand_executor,  // Dedicated for rand operations
        secret_share_executor,  // Dedicated for secret sharing
        rand_storage.clone(),
        node_config.consensus_observer,
        consensus_publisher.clone(),
    ));
    
    // ... EpochManager gets dag_executor for DAG operations
}
```

**Long-term fix**: Implement a hierarchical resource management system with per-component quotas and priority-based scheduling to ensure critical consensus operations are never starved.

**Configuration update**: Add separate configuration parameters for each component's executor capacity with appropriate defaults based on expected message volumes.

## Proof of Concept

```rust
// PoC: Demonstrate capacity exhaustion across components
#[tokio::test]
async fn test_bounded_executor_shared_capacity_exhaustion() {
    use aptos_bounded_executor::BoundedExecutor;
    use std::sync::{Arc, atomic::{AtomicU32, Ordering}};
    use tokio::time::{timeout, Duration};
    
    let rt = tokio::runtime::Runtime::new().unwrap();
    let executor = BoundedExecutor::new(4, rt.handle().clone());
    
    // Simulate RandManager clone
    let rand_executor = executor.clone();
    
    // Simulate SecretShareManager clone
    let secret_executor = executor.clone();
    
    let blocked_count = Arc::new(AtomicU32::new(0));
    let blocked_count_clone = blocked_count.clone();
    
    // Simulate RandManager flooding the executor with verification tasks
    for i in 0..8 {
        let rand_executor = rand_executor.clone();
        tokio::spawn(async move {
            // These will consume all 4 permits
            let _handle = rand_executor.spawn(async move {
                tokio::time::sleep(Duration::from_secs(10)).await;
                println!("RandManager task {} completed", i);
            }).await;
        });
    }
    
    // Give time for rand tasks to consume permits
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Now SecretShareManager tries to spawn but will block
    let secret_task = tokio::spawn(async move {
        let result = timeout(
            Duration::from_millis(500),
            secret_executor.spawn(async {
                println!("SecretShare task started");
            })
        ).await;
        
        if result.is_err() {
            blocked_count_clone.fetch_add(1, Ordering::SeqCst);
            println!("SecretShare task BLOCKED - capacity exhausted!");
        }
    });
    
    secret_task.await.unwrap();
    
    // Verify that SecretShareManager was starved
    assert_eq!(blocked_count.load(Ordering::SeqCst), 1, 
        "SecretShareManager should be blocked when RandManager exhausts shared capacity");
}
```

**Attack simulation steps:**
1. Deploy a malicious client that connects to a validator node
2. Flood the validator with serialized `RandMessage::Share` RPC messages at high rate (>100 msg/sec)
3. Monitor validator metrics for increased message queue depth and reduced consensus participation
4. Observe validator falling behind in consensus rounds due to blocked DAG/randomness/secret-sharing operations
5. Validator experiences liveness failure and accumulates failed rounds in reputation tracking

**Notes:**

This vulnerability represents a fundamental resource isolation failure in the consensus layer. The unintended capacity sharing violates the principle of fault isolation between consensus components. While individual components were designed with concurrency limits via `BoundedExecutor`, the implementation inadvertently creates a shared bottleneck that can be exploited to cause validator liveness failure. The fix requires careful architectural consideration to maintain performance while ensuring proper resource isolation.

### Citations

**File:** crates/bounded-executor/src/executor.rs (L16-20)
```rust
#[derive(Clone, Debug)]
pub struct BoundedExecutor {
    semaphore: Arc<Semaphore>,
    executor: Handle,
}
```

**File:** consensus/src/consensus_provider.rs (L81-84)
```rust
    let bounded_executor = BoundedExecutor::new(
        node_config.consensus.num_bounded_executor_tasks as usize,
        runtime.handle().clone(),
    );
```

**File:** consensus/src/consensus_provider.rs (L87-97)
```rust
    let execution_client = Arc::new(ExecutionProxyClient::new(
        node_config.consensus.clone(),
        Arc::new(execution_proxy),
        node_config.validator_network.as_ref().unwrap().peer_id(),
        self_sender.clone(),
        consensus_network_client.clone(),
        bounded_executor.clone(),
        rand_storage.clone(),
        node_config.consensus_observer,
        consensus_publisher.clone(),
    ));
```

**File:** consensus/src/consensus_provider.rs (L99-115)
```rust
    let epoch_mgr = EpochManager::new(
        node_config,
        time_service,
        self_sender,
        consensus_network_client,
        timeout_sender,
        consensus_to_mempool_sender,
        execution_client,
        storage.clone(),
        quorum_store_db.clone(),
        reconfig_events,
        bounded_executor,
        aptos_time_service::TimeService::real(),
        vtxn_pool,
        rand_storage,
        consensus_publisher,
    );
```

**File:** consensus/src/pipeline/execution_client.rs (L240-260)
```rust
        let rand_manager = RandManager::<Share, AugmentedData>::new(
            self.author,
            epoch_state.clone(),
            signer,
            rand_config,
            fast_rand_config,
            rand_ready_block_tx,
            network_sender.clone(),
            self.rand_storage.clone(),
            self.bounded_executor.clone(),
            &self.consensus_config.rand_rb_config,
        );

        tokio::spawn(rand_manager.start(
            ordered_block_rx,
            rand_msg_rx,
            reset_rand_manager_rx,
            self.bounded_executor.clone(),
            highest_committed_round,
        ));

```

**File:** consensus/src/pipeline/execution_client.rs (L286-300)
```rust
        let secret_share_manager = SecretShareManager::new(
            self.author,
            epoch_state.clone(),
            config,
            secret_ready_block_tx,
            network_sender.clone(),
            self.bounded_executor.clone(),
            &self.consensus_config.rand_rb_config,
        );

        tokio::spawn(secret_share_manager.start(
            ordered_block_rx,
            secret_sharing_msg_rx,
            reset_secret_share_manager_rx,
            self.bounded_executor.clone(),
```

**File:** consensus/src/epoch_manager.rs (L1488-1513)
```rust
        let bootstrapper = DagBootstrapper::new(
            self.author,
            self.dag_config.clone(),
            onchain_dag_consensus_config.clone(),
            signer,
            epoch_state.clone(),
            dag_storage,
            network_sender_arc.clone(),
            network_sender_arc.clone(),
            network_sender_arc,
            self.aptos_time_service.clone(),
            payload_manager,
            payload_client,
            self.execution_client
                .get_execution_channel()
                .expect("unable to get execution channel"),
            self.execution_client.clone(),
            onchain_consensus_config.quorum_store_enabled(),
            onchain_consensus_config.effective_validator_txn_config(),
            onchain_randomness_config,
            onchain_jwk_consensus_config,
            self.bounded_executor.clone(),
            self.config
                .quorum_store
                .allow_batches_without_pos_in_proposal,
        );
```

**File:** consensus/src/rand/rand_gen/rand_manager.rs (L221-261)
```rust
    async fn verification_task(
        epoch_state: Arc<EpochState>,
        mut incoming_rpc_request: aptos_channel::Receiver<Author, IncomingRandGenRequest>,
        verified_msg_tx: UnboundedSender<RpcRequest<S, D>>,
        rand_config: RandConfig,
        fast_rand_config: Option<RandConfig>,
        bounded_executor: BoundedExecutor,
    ) {
        while let Some(rand_gen_msg) = incoming_rpc_request.next().await {
            let tx = verified_msg_tx.clone();
            let epoch_state_clone = epoch_state.clone();
            let config_clone = rand_config.clone();
            let fast_config_clone = fast_rand_config.clone();
            bounded_executor
                .spawn(async move {
                    match bcs::from_bytes::<RandMessage<S, D>>(rand_gen_msg.req.data()) {
                        Ok(msg) => {
                            if msg
                                .verify(
                                    &epoch_state_clone,
                                    &config_clone,
                                    &fast_config_clone,
                                    rand_gen_msg.sender,
                                )
                                .is_ok()
                            {
                                let _ = tx.unbounded_send(RpcRequest {
                                    req: msg,
                                    protocol: rand_gen_msg.protocol,
                                    response_sender: rand_gen_msg.response_sender,
                                });
                            }
                        },
                        Err(e) => {
                            warn!("Invalid rand gen message: {}", e);
                        },
                    }
                })
                .await;
        }
    }
```

**File:** consensus/src/rand/secret_sharing/secret_share_manager.rs (L205-235)
```rust
    async fn verification_task(
        epoch_state: Arc<EpochState>,
        mut incoming_rpc_request: aptos_channel::Receiver<Author, IncomingSecretShareRequest>,
        verified_msg_tx: UnboundedSender<SecretShareRpc>,
        config: SecretShareConfig,
        bounded_executor: BoundedExecutor,
    ) {
        while let Some(dec_msg) = incoming_rpc_request.next().await {
            let tx = verified_msg_tx.clone();
            let epoch_state_clone = epoch_state.clone();
            let config_clone = config.clone();
            bounded_executor
                .spawn(async move {
                    match bcs::from_bytes::<SecretShareMessage>(dec_msg.req.data()) {
                        Ok(msg) => {
                            if msg.verify(&epoch_state_clone, &config_clone).is_ok() {
                                let _ = tx.unbounded_send(SecretShareRpc {
                                    msg,
                                    protocol: dec_msg.protocol,
                                    response_sender: dec_msg.response_sender,
                                });
                            }
                        },
                        Err(e) => {
                            warn!("Invalid dec message: {}", e);
                        },
                    }
                })
                .await;
        }
    }
```

**File:** consensus/src/dag/dag_handler.rs (L88-109)
```rust
        // TODO: feed in the executor based on verification Runtime
        let mut verified_msg_stream = concurrent_map(
            dag_rpc_rx,
            executor.clone(),
            move |rpc_request: IncomingDAGRequest| {
                let epoch_state = epoch_state.clone();
                async move {
                    let epoch = rpc_request.req.epoch();
                    let result = rpc_request
                        .req
                        .try_into()
                        .and_then(|dag_message: DAGMessage| {
                            monitor!(
                                "dag_message_verify",
                                dag_message.verify(rpc_request.sender, &epoch_state.verifier)
                            )?;
                            Ok(dag_message)
                        });
                    (result, epoch, rpc_request.sender, rpc_request.responder)
                }
            },
        );
```

**File:** crates/reliable-broadcast/src/lib.rs (L169-181)
```rust
                    Some((receiver, result)) = rpc_futures.next() => {
                        let aggregating = aggregating.clone();
                        let future = executor.spawn(async move {
                            (
                                    receiver,
                                    result
                                        .and_then(|msg| {
                                            msg.try_into().map_err(|e| anyhow::anyhow!("{:?}", e))
                                        })
                                        .and_then(|ack| aggregating.add(receiver, ack)),
                            )
                        }).await;
                        aggregate_futures.push(future);
```

**File:** config/src/config/consensus_config.rs (L379-379)
```rust
            num_bounded_executor_tasks: 16,
```
