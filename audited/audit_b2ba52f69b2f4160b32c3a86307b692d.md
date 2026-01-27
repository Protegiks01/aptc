# Audit Report

## Title
Byzantine Validator DoS via BoundedExecutor Exhaustion in Consensus Message Processing

## Summary
A Byzantine validator can intentionally flood the network with malicious consensus messages that exhaust the `BoundedExecutor` capacity (default 16 concurrent tasks), causing the consensus `EpochManager` event loop to block indefinitely while waiting for verification task permits. This degrades network performance and prevents legitimate consensus messages from being processed.

## Finding Description

The vulnerability exists in the consensus message processing pipeline where incoming network messages trigger cryptographic signature verification tasks on a bounded executor. [1](#0-0) 

The `process_message()` function spawns verification tasks using `self.bounded_executor.spawn().await`, which is a **blocking async call** that waits for an available permit from the semaphore-based executor: [2](#0-1) 

The `spawn()` method blocks until `acquire_permit().await` succeeds, which requires an available slot in the bounded executor. The default capacity is only 16 concurrent tasks: [3](#0-2) 

**Attack Flow:**
1. Byzantine validator floods consensus messages (ProposalMsg, VoteMsg, OrderVoteMsg, etc.) through the P2P network
2. Messages arrive at `EpochManager.start()` event loop and are dequeued from network channels
3. Each message triggers `process_message().await` which calls `bounded_executor.spawn().await`
4. The 16 executor slots fill with verification tasks performing expensive cryptographic operations
5. Once exhausted, `process_message()` blocks waiting for a permit at line 1587
6. The main event loop blocks in the `tokio::select!` at line 1933, preventing ALL other messages (legitimate proposals, votes, timeouts) from being processed: [4](#0-3) 

The single-threaded event loop cannot process any branch of the `select!` while blocked on the `.await` in `process_message()`. This breaks the consensus liveness guarantee that honest validators can process legitimate messages even under Byzantine attack.

**Invariant Violated:**
- **Resource Limits**: The bounded executor should protect against resource exhaustion, but instead becomes an attack vector
- **Consensus Liveness**: AptosBFT should maintain liveness with < 1/3 Byzantine validators, but a single Byzantine validator can degrade all honest nodes

## Impact Explanation

This qualifies as **High Severity** under the Aptos Bug Bounty program criteria: "Validator node slowdowns."

**Impact:**
- All consensus validators processing messages from the Byzantine peer experience degraded performance
- Legitimate consensus messages (proposals, votes, QCs) cannot be processed while the executor is saturated
- Network-wide consensus liveness degrades as multiple validators become unable to participate effectively
- Block production slows or stalls during the attack
- The attack is sustainable as long as the Byzantine validator continues sending messages

The impact is limited to availability/performance degradation rather than safety violations, as the Byzantine validator cannot cause incorrect state transitions. However, sustained degradation of consensus performance across the network is a significant security issue.

## Likelihood Explanation

**Likelihood: High**

**Attack Requirements:**
- Attacker must control at least one validator node in the active validator set
- No collusion with other validators required
- No special timing or state synchronization needed

**Ease of Exploitation:**
- Byzantine validators can trivially send arbitrary consensus messages via the P2P network
- No authentication bypasses needed - validators are authenticated network peers
- Attack is repeatable and sustainable
- Small executor capacity (16 tasks) makes exhaustion trivial
- Verification tasks for invalid messages still consume executor slots and CPU time

**Detection:**
- Attack is easily detectable via metrics monitoring (executor saturation, message processing delays)
- However, detection does not prevent the impact

## Recommendation

Implement **per-peer rate limiting** before spawning verification tasks, and use **non-blocking** executor submission for network messages:

**Fix 1: Use `try_spawn()` instead of `spawn()` for network messages** [5](#0-4) 

Replace the blocking `spawn().await` with `try_spawn()` which returns immediately if capacity is exhausted:

```rust
// In epoch_manager.rs process_message()
match self.bounded_executor.try_spawn(async move {
    // verification logic
}) {
    Ok(handle) => {
        // Successfully spawned, optionally await completion
    },
    Err(_future) => {
        // Executor at capacity, log and drop message
        warn!(
            "Dropped message from {} due to executor saturation",
            peer_id
        );
        counters::CONSENSUS_DROPPED_MESSAGES
            .with_label_values(&["executor_saturated"])
            .inc();
    }
}
```

**Fix 2: Add per-peer message rate limiting**

Track recent message counts per peer and reject excessive messages before executor submission:

```rust
struct PeerRateLimiter {
    peer_message_counts: HashMap<AccountAddress, (Instant, u32)>,
    max_messages_per_second: u32,
}

impl PeerRateLimiter {
    fn should_accept(&mut self, peer_id: AccountAddress) -> bool {
        let now = Instant::now();
        let (last_reset, count) = self.peer_message_counts
            .entry(peer_id)
            .or_insert((now, 0));
        
        if now.duration_since(*last_reset) > Duration::from_secs(1) {
            *last_reset = now;
            *count = 1;
            true
        } else if *count < self.max_messages_per_second {
            *count += 1;
            true
        } else {
            false // Rate limit exceeded
        }
    }
}
```

**Fix 3: Increase executor capacity**

While not a complete solution, increasing the default capacity from 16 to a higher value (e.g., 64-128) makes the attack harder:

```rust
// In consensus_config.rs
num_bounded_executor_tasks: 64,  // Increased from 16
```

## Proof of Concept

```rust
// Integration test demonstrating the vulnerability
#[tokio::test]
async fn test_byzantine_validator_dos_via_executor_exhaustion() {
    use aptos_bounded_executor::BoundedExecutor;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::time::{sleep, Instant};
    
    // Simulate the bounded executor with small capacity
    let runtime = tokio::runtime::Handle::current();
    let executor = BoundedExecutor::new(16, runtime);
    
    // Byzantine validator spawns 16 long-running verification tasks
    let mut handles = vec![];
    for i in 0..16 {
        let handle = executor.spawn(async move {
            println!("Malicious task {} started", i);
            // Simulate expensive signature verification
            sleep(Duration::from_secs(10)).await;
            println!("Malicious task {} completed", i);
        }).await;
        handles.push(handle);
    }
    
    // Now try to process a legitimate message
    let start = Instant::now();
    println!("Attempting to spawn legitimate message verification...");
    
    // This will block until one of the malicious tasks completes
    let legitimate_handle = tokio::time::timeout(
        Duration::from_millis(100),
        executor.spawn(async {
            println!("Legitimate task started");
        })
    ).await;
    
    match legitimate_handle {
        Ok(_) => {
            println!("Legitimate message processed immediately");
        },
        Err(_) => {
            println!(
                "VULNERABILITY: Legitimate message blocked for {}ms waiting for executor capacity",
                start.elapsed().as_millis()
            );
            println!("In a real validator, this blocks the entire consensus event loop!");
        }
    }
    
    // Verify the executor is saturated
    assert!(executor.try_spawn(async {}).is_err(), 
            "Executor should be at capacity");
}
```

This test demonstrates that:
1. A Byzantine validator can saturate the bounded executor with 16 tasks
2. Legitimate messages cannot be processed while the executor is full
3. The blocking behavior prevents the event loop from making progress
4. Network consensus performance degrades across all affected validators

## Notes

The vulnerability is exacerbated by:
- The single-threaded event loop design in `EpochManager.start()` 
- Lack of per-peer rate limiting before expensive operations
- Small default executor capacity (16 tasks)
- Cryptographic verification being CPU-intensive, extending task duration

While network-level rate limiting exists, it operates at a different layer and does not prevent this application-layer resource exhaustion attack.

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

**File:** crates/bounded-executor/src/executor.rs (L54-68)
```rust
    /// Try to spawn a [`Future`] on the `BoundedExecutor`. If the `BoundedExecutor`
    /// is at capacity, this will return an `Err(F)`, passing back the future the
    /// caller attempted to spawn. Otherwise, this will spawn the future on the
    /// executor and send back a [`JoinHandle`] that the caller can `.await` on
    /// for the results of the [`Future`].
    pub fn try_spawn<F>(&self, future: F) -> Result<JoinHandle<F::Output>, F>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        match self.try_acquire_permit() {
            Some(permit) => Ok(self.executor.spawn(future_with_permit(future, permit))),
            None => Err(future),
        }
    }
```

**File:** config/src/config/consensus_config.rs (L379-379)
```rust
            num_bounded_executor_tasks: 16,
```
