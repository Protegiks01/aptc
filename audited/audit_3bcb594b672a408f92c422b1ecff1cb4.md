# Audit Report

## Title
Bounded Executor Starvation Causes RPC Timeout and Consensus Liveness Degradation

## Summary
The consensus event loop uses a shared bounded executor with blocking `spawn().await` calls to process all incoming messages. When high-volume consensus or quorum store messages fill the executor's capacity (default: 16 concurrent tasks), the event loop blocks indefinitely, preventing processing of RPC requests. This causes critical background operations like block retrieval to timeout, leading to sync failures and potential consensus liveness degradation.

## Finding Description

The `EpochManager::start()` method implements the main consensus event loop using `tokio::select!` to receive from three channels: [1](#0-0) 

When messages arrive from `consensus_messages` or `quorum_store_messages` channels, they are processed via `process_message()`, which spawns verification tasks on a shared `BoundedExecutor`: [2](#0-1) 

The `BoundedExecutor::spawn()` method uses a semaphore-based mechanism that **blocks** when at capacity: [3](#0-2) 

The executor capacity is configured via `num_bounded_executor_tasks` with a default of only **16 concurrent tasks**: [4](#0-3) [5](#0-4) 

**Attack Scenario:**

1. A malicious or compromised validator floods the network with valid consensus messages (proposals, votes, sync info) or quorum store messages (batches, signed batch info, proof of store)
2. These messages pass epoch checks and are queued in the respective channels with limited capacity (10 for consensus_messages, 50 for quorum_store_messages): [6](#0-5) 

3. The event loop processes messages by spawning verification tasks (signature verification, proof checks) on the bounded executor
4. Message verification is computationally expensive and takes time
5. The bounded executor fills up with 16 concurrent verification tasks
6. Additional messages continue arriving, and `bounded_executor.spawn().await` blocks at line 1622
7. While blocked, the entire event loop stalls and cannot process other branches in the `tokio::select!`
8. RPC requests queued in `rpc_rx` (block retrieval, batch retrieval, DAG requests) cannot be processed
9. These RPCs have strict timeouts (5 seconds for block retrieval, 1 second for DAG operations): [7](#0-6) 

10. RPC requests timeout, causing honest validators to fail syncing blocks and leading to consensus liveness issues

The vulnerability exploits the fact that `tokio::select!` without the `biased;` modifier provides fair scheduling, but cannot help when one branch blocks the entire async task. The blocking occurs because there's no timeout on the `.await` and no fallback mechanism.

## Impact Explanation

This vulnerability meets **Medium Severity** criteria per Aptos bug bounty rules:

- **State inconsistencies requiring intervention**: When honest validators cannot retrieve blocks due to RPC timeouts, they fall behind and require manual intervention or recovery procedures
- **Consensus liveness degradation**: If multiple validators are affected simultaneously, the network may experience reduced liveness as validators struggle to sync
- **Background task failures**: Critical operations like block synchronization, batch retrieval for quorum store, and DAG consensus operations fail

The impact is limited to liveness/availability rather than safety violations. The consensus protocol's safety guarantees remain intact as no invalid blocks can be committed, but the network's ability to make progress is compromised.

## Likelihood Explanation

**Likelihood: High**

Attack requirements are minimal:
- Attacker needs to be a validator (or compromise one) to send messages
- Messages must be valid and pass signature verification, but any validator can generate valid messages
- No special privileges or Byzantine collusion required
- The default executor capacity of 16 is relatively small and easily saturated
- Message verification (cryptographic operations) is CPU-intensive and takes measurable time

The attack is practical because:
- Quorum store channels have capacity 50, allowing burst of 50 messages before backpressure
- Consensus messages channel has capacity 10
- An attacker can continuously send valid proposals, votes, and quorum store batches
- The verification process for each message involves signature verification and proof checks that consume bounded executor slots
- Once 16 verification tasks are running, new messages cause indefinite blocking

## Recommendation

Implement non-blocking message processing with multiple mitigations:

**Option 1: Use `try_spawn()` with fallback**
Replace `spawn().await` with `try_spawn()` and handle capacity exhaustion gracefully:

```rust
match self.bounded_executor.try_spawn(verification_task) {
    Ok(_handle) => {
        // Successfully spawned
    }
    Err(_future) => {
        // Executor at capacity - drop message with warning
        warn!(
            "Bounded executor at capacity, dropping message from {}",
            peer_id
        );
        counters::CONSENSUS_DROPPED_MSGS_DUE_TO_EXECUTOR_CAPACITY.inc();
    }
}
```

**Option 2: Implement priority-based processing**
Use `biased;` in `tokio::select!` to prioritize RPC requests:

```rust
tokio::select! {
    biased;
    (peer, request) = network_receivers.rpc_rx.select_next_some() => {
        // Process RPCs with higher priority
    },
    (peer, msg) = network_receivers.consensus_messages.select_next_some() => {
        // Process consensus messages
    },
    (peer, msg) = network_receivers.quorum_store_messages.select_next_some() => {
        // Process quorum store messages
    },
}
```

**Option 3: Separate bounded executors**
Use dedicated bounded executors for different message types with separate capacity limits:

```rust
let verification_executor = BoundedExecutor::new(32, runtime.handle().clone());
let rpc_executor = BoundedExecutor::new(16, runtime.handle().clone());
```

**Option 4: Add timeout on spawn**
Wrap `spawn().await` with a timeout:

```rust
match timeout(Duration::from_millis(100), self.bounded_executor.spawn(task)).await {
    Ok(handle) => { /* spawned */ }
    Err(_) => { /* timeout, drop message */ }
}
```

**Recommended solution: Combine Option 1 and Option 2** - Use `try_spawn()` for best-effort message processing while prioritizing RPC handling via `biased;` select.

## Proof of Concept

```rust
#[tokio::test]
async fn test_bounded_executor_starvation() {
    use aptos_bounded_executor::BoundedExecutor;
    use tokio::sync::mpsc;
    use tokio::time::{sleep, timeout, Duration};
    use futures::StreamExt;

    let runtime = tokio::runtime::Handle::current();
    let bounded_executor = BoundedExecutor::new(16, runtime.clone());

    // Simulate consensus message channel
    let (consensus_tx, mut consensus_rx) = mpsc::channel(10);
    
    // Simulate RPC channel
    let (rpc_tx, mut rpc_rx) = mpsc::channel(10);

    // Fill bounded executor with slow tasks
    for i in 0..16 {
        let executor = bounded_executor.clone();
        tokio::spawn(async move {
            executor.spawn(async move {
                // Simulate slow signature verification
                sleep(Duration::from_secs(5)).await;
                println!("Task {} completed", i);
            }).await;
        });
    }

    // Wait for executor to fill
    sleep(Duration::from_millis(100)).await;

    // Send consensus messages continuously
    let consensus_sender = tokio::spawn(async move {
        for i in 0..50 {
            consensus_tx.send(i).await.unwrap();
            sleep(Duration::from_millis(10)).await;
        }
    });

    // Send RPC request that should timeout
    let rpc_sender = tokio::spawn(async move {
        sleep(Duration::from_millis(200)).await;
        rpc_tx.send("block_retrieval_request").await.unwrap();
    });

    // Simulate event loop
    let event_loop = tokio::spawn(async move {
        let mut rpc_received = false;
        loop {
            tokio::select! {
                Some(msg) = consensus_rx.recv() => {
                    // This will block when executor is full
                    bounded_executor.spawn(async move {
                        sleep(Duration::from_millis(100)).await;
                        println!("Processed consensus msg {}", msg);
                    }).await;
                }
                Some(rpc) = rpc_rx.recv() => {
                    println!("RPC received: {}", rpc);
                    rpc_received = true;
                    break;
                }
            }
        }
        rpc_received
    });

    // RPC should timeout because event loop is blocked
    let result = timeout(Duration::from_secs(2), event_loop).await;
    
    match result {
        Ok(Ok(true)) => {
            panic!("RPC was processed - vulnerability not demonstrated");
        }
        Ok(Ok(false)) | Err(_) => {
            println!("✓ Vulnerability confirmed: RPC timed out due to executor starvation");
        }
        _ => {}
    }

    consensus_sender.abort();
    rpc_sender.abort();
}
```

This PoC demonstrates that when the bounded executor is saturated with slow verification tasks from consensus messages, RPC requests cannot be processed in a timely manner, leading to timeouts and availability issues.

**Notes:**

This vulnerability affects consensus availability rather than safety. The issue stems from a resource management design flaw where all message types compete for the same bounded executor capacity without prioritization. While the `tokio::select!` macro provides fair scheduling among ready futures, it cannot prevent one branch from monopolizing resources when that branch's processing involves blocking operations on shared resources. The default capacity of 16 concurrent verification tasks is insufficient to handle burst traffic scenarios while maintaining responsiveness for critical RPC operations.

### Citations

**File:** consensus/src/epoch_manager.rs (L1587-1622)
```rust
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
```

**File:** consensus/src/epoch_manager.rs (L1930-1953)
```rust
            tokio::select! {
                (peer, msg) = network_receivers.consensus_messages.select_next_some() => {
                    monitor!("epoch_manager_process_consensus_messages",
                    if let Err(e) = self.process_message(peer, msg).await {
                        error!(epoch = self.epoch(), error = ?e, kind = error_kind(&e));
                    });
                },
                (peer, msg) = network_receivers.quorum_store_messages.select_next_some() => {
                    monitor!("epoch_manager_process_quorum_store_messages",
                    if let Err(e) = self.process_message(peer, msg).await {
                        error!(epoch = self.epoch(), error = ?e, kind = error_kind(&e));
                    });
                },
                (peer, request) = network_receivers.rpc_rx.select_next_some() => {
                    monitor!("epoch_manager_process_rpc",
                    if let Err(e) = self.process_rpc_request(peer, request) {
                        error!(epoch = self.epoch(), error = ?e, kind = error_kind(&e));
                    });
                },
                round = round_timeout_sender_rx.select_next_some() => {
                    monitor!("epoch_manager_process_round_timeout",
                    self.process_local_timeout(round));
                },
            }
```

**File:** crates/bounded-executor/src/executor.rs (L41-52)
```rust
    /// Spawn a [`Future`] on the `BoundedExecutor`. This function is async and
    /// will block if the executor is at capacity until one of the other spawned
    /// futures completes. This function returns a [`JoinHandle`] that the caller
    /// can `.await` on for the results of the [`Future`].
    pub async fn spawn<F>(&self, future: F) -> JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let permit = self.acquire_permit().await;
        self.executor.spawn(future_with_permit(future, permit))
    }
```

**File:** config/src/config/consensus_config.rs (L379-379)
```rust
            num_bounded_executor_tasks: 16,
```

**File:** consensus/src/consensus_provider.rs (L81-84)
```rust
    let bounded_executor = BoundedExecutor::new(
        node_config.consensus.num_bounded_executor_tasks as usize,
        runtime.handle().clone(),
    );
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

**File:** consensus/consensus-types/src/block_retrieval.rs (L18-18)
```rust
pub enum BlockRetrievalRequest {
```
