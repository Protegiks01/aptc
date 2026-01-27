# Audit Report

## Title
VFN Mempool Resource Exhaustion via Unbounded Slow Sync Attacks

## Summary
Validator Full Nodes (VFNs) are vulnerable to resource exhaustion attacks through malicious peers exploiting the increased `shared_mempool_max_concurrent_inbound_syncs` limit of 16. A single malicious peer can occupy all 16 bounded executor slots with slow transaction processing tasks, causing the VFN's mempool coordinator to block and rendering the node unable to serve API requests or process transactions from legitimate peers. [1](#0-0) 

## Finding Description
The VFN configuration optimization increases the concurrent inbound sync limit from the default of 4 to 16 slots to improve throughput. However, this creates an exploitable attack surface due to three critical design flaws:

**1. Global Shared Resource Pool Without Per-Peer Limits**

The bounded executor with 16 slots is shared globally across ALL peers and client API requests. There is no per-peer limit on how many slots a single malicious peer can occupy. [2](#0-1) 

When network events arrive, the coordinator processes them sequentially and spawns tasks via the bounded executor for peer broadcasts, client requests, and reconfig events: [3](#0-2) 

**2. Blocking Task Spawning Without Timeout**

The `BoundedExecutor::spawn()` method blocks until a permit is available, with no timeout mechanism: [4](#0-3) 

When the coordinator attempts to spawn a task but all 16 slots are occupied, it blocks waiting for a permit. During this blocking period, the coordinator's event loop cannot process ANY other events, including client API requests, reconfig notifications, or broadcasts from other peers: [5](#0-4) 

**3. No Task Execution Timeout**

Transaction processing tasks perform multiple potentially slow operations without timeouts:
- Database reads for state checkpoint views
- Parallel I/O for account sequence number fetching
- Parallel VM validation for up to 300 transactions per batch [6](#0-5) [7](#0-6) 

**Attack Execution Path:**

1. Malicious peer connects to VFN
2. Attacker sends 16 concurrent `BroadcastTransactionsRequest` messages in rapid succession
3. Each message contains up to 300 transactions (the `shared_mempool_batch_size` limit)
4. Attacker crafts transactions to maximize processing time:
   - Target 300 different accounts to maximize DB reads
   - Include complex transaction payloads to slow VM validation
   - Send transactions that will eventually fail validation (waste processing time)
5. All 16 bounded executor slots become occupied by slow-running tasks
6. When a 17th event arrives (e.g., legitimate client API request), the coordinator blocks attempting to acquire a permit
7. VFN becomes unresponsive for:
   - Client API transaction submissions
   - Transaction broadcasts from other peers  
   - Reconfig event processing
   - All mempool operations

## Impact Explanation
This vulnerability qualifies as **High Severity** per the Aptos bug bounty criteria:

- **"Validator node slowdowns"**: VFNs experience severe service degradation, becoming unable to process API requests or sync transactions
- **"API crashes"**: While not a crash, the API becomes effectively unresponsive when the coordinator is blocked

The attack causes:
- **Availability Impact**: VFN cannot serve user transaction submissions via API
- **Network Health Impact**: VFN cannot propagate transactions from upstream validators to downstream peers
- **Service Degradation**: All mempool operations halt while waiting for bounded executor permits

While VFNs are not validators and don't participate in consensus, they are critical infrastructure for:
- Serving API requests from users and applications
- Relaying transactions between network tiers
- Supporting ecosystem functionality

## Likelihood Explanation
This vulnerability is **highly likely** to be exploited:

**Attacker Requirements:**
- Ability to connect as a peer to a VFN (trivial - VFNs accept connections from public fullnodes)
- Knowledge of the mempool message format (publicly documented)
- Ability to craft and send transactions (standard blockchain operation)

**Attack Complexity:** Low
- No special privileges required
- No cryptographic operations needed
- Simple flood of concurrent messages with crafted transactions

**Detection Difficulty:** Medium
- Attack appears as legitimate transaction traffic initially
- Gradual degradation may be mistaken for network congestion
- Monitoring would show high task spawn latency metrics

The configuration change specifically affects VFNs (not validators), which are more exposed to untrusted peers in the network topology, increasing attack likelihood.

## Recommendation

Implement multi-layered protections:

**1. Add Per-Peer Concurrency Limits:**
```rust
// In MempoolConfig
pub struct MempoolConfig {
    // ... existing fields ...
    pub max_concurrent_inbound_syncs_per_peer: usize,
}

impl Default for MempoolConfig {
    fn default() -> MempoolConfig {
        MempoolConfig {
            // ... existing defaults ...
            max_concurrent_inbound_syncs_per_peer: 2, // Limit per peer
        }
    }
}
```

Track per-peer slot usage in the coordinator and reject new requests when a peer exceeds its limit.

**2. Add Task Execution Timeout:**
```rust
// In process_received_txns
use tokio::time::{timeout, Duration};

const TRANSACTION_PROCESSING_TIMEOUT: Duration = Duration::from_secs(5);

let result = timeout(
    TRANSACTION_PROCESSING_TIMEOUT,
    bounded_executor.spawn(tasks::process_transaction_broadcast(...))
).await;

match result {
    Ok(_) => { /* Task completed */ },
    Err(_) => {
        warn!("Transaction processing timeout for peer {:?}", peer);
        counters::TRANSACTION_PROCESSING_TIMEOUT.inc();
        // Send error response to peer
    }
}
```

**3. Use try_spawn Instead of spawn:**
```rust
// In process_received_txns
match bounded_executor.try_spawn(tasks::process_transaction_broadcast(...)) {
    Ok(_) => { /* Task spawned */ },
    Err(_) => {
        warn!("Bounded executor at capacity, rejecting peer {:?}", peer);
        counters::BOUNDED_EXECUTOR_FULL.inc();
        // Send backpressure signal to peer
    }
}
```

This prevents the coordinator from blocking and maintains responsiveness.

**4. Separate Bounded Executors:**
```rust
// Create separate bounded executors for different event sources
let client_bounded_executor = BoundedExecutor::new(4, executor.clone());
let peer_bounded_executor = BoundedExecutor::new(12, executor.clone());
let reconfig_bounded_executor = BoundedExecutor::new(2, executor.clone());
```

This ensures client API requests are never blocked by malicious peer traffic.

## Proof of Concept

```rust
// Integration test demonstrating the attack
#[tokio::test]
async fn test_vfn_resource_exhaustion_attack() {
    // Setup VFN with 16 concurrent inbound syncs
    let mut config = NodeConfig::get_default_vfn_config();
    config.mempool.shared_mempool_max_concurrent_inbound_syncs = 16;
    
    // Start VFN
    let vfn = setup_vfn_node(config).await;
    
    // Malicious peer crafts slow transactions
    let slow_txns: Vec<SignedTransaction> = (0..300)
        .map(|i| create_transaction_with_complex_payload(
            AccountAddress::random(), // Different account each time
            i,
            create_complex_script(), // Slow to validate
        ))
        .collect();
    
    // Attack: Send 16 concurrent broadcast requests
    let mut attack_handles = vec![];
    for _ in 0..16 {
        let txns = slow_txns.clone();
        let vfn_client = vfn.mempool_client.clone();
        
        attack_handles.push(tokio::spawn(async move {
            vfn_client.send_broadcast_request(
                MempoolSyncMsg::BroadcastTransactionsRequest {
                    message_id: MempoolMessageId::new(),
                    transactions: txns,
                }
            ).await
        }));
    }
    
    // Wait for attack to take effect
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Verify VFN is unresponsive to legitimate client requests
    let client_submit_start = Instant::now();
    let legitimate_txn = create_valid_transaction();
    let result = tokio::time::timeout(
        Duration::from_secs(1),
        vfn.submit_transaction(legitimate_txn)
    ).await;
    
    // Attack successful if client request times out
    assert!(result.is_err(), "VFN should be unresponsive during attack");
    assert!(
        client_submit_start.elapsed() >= Duration::from_secs(1),
        "Client request should timeout"
    );
    
    // Verify metrics show all bounded executor slots occupied
    let metrics = vfn.get_metrics();
    assert_eq!(
        metrics.get("aptos_mempool_bounded_executor_busy_slots"), 
        Some(16)
    );
}
```

## Notes

This vulnerability is particularly concerning because:

1. **VFN-specific**: The configuration optimization specifically targets VFNs, which are more exposed to untrusted peers than validators
2. **Architectural flaw**: The shared bounded executor design without per-peer limits is a fundamental architectural issue
3. **No existing mitigations**: Current rate limiting (`max_broadcasts_per_peer`) only limits outbound broadcasts, not inbound processing
4. **Cascading effects**: Blocking the coordinator affects ALL mempool operations, not just transaction processing

The fix requires careful consideration of resource allocation between different event sources (peers vs. clients) and implementing proper timeout mechanisms throughout the transaction processing pipeline.

### Citations

**File:** config/src/config/mempool_config.rs (L215-220)
```rust
        if node_type.is_validator_fullnode() {
            // Set the shared_mempool_max_concurrent_inbound_syncs to 16 (default is 4)
            if local_mempool_config_yaml["shared_mempool_max_concurrent_inbound_syncs"].is_null() {
                mempool_config.shared_mempool_max_concurrent_inbound_syncs = 16;
                modified_config = true;
            }
```

**File:** mempool/src/shared_mempool/coordinator.rs (L90-93)
```rust
    // Use a BoundedExecutor to restrict only `workers_available` concurrent
    // worker tasks that can process incoming transactions.
    let workers_available = smp.config.shared_mempool_max_concurrent_inbound_syncs;
    let bounded_executor = BoundedExecutor::new(workers_available, executor.clone());
```

**File:** mempool/src/shared_mempool/coordinator.rs (L106-129)
```rust
    loop {
        let _timer = counters::MAIN_LOOP.start_timer();
        ::futures::select! {
            msg = client_events.select_next_some() => {
                handle_client_request(&mut smp, &bounded_executor, msg).await;
            },
            msg = quorum_store_requests.select_next_some() => {
                tasks::process_quorum_store_request(&smp, msg);
            },
            reconfig_notification = mempool_reconfig_events.select_next_some() => {
                handle_mempool_reconfig_event(&mut smp, &bounded_executor, reconfig_notification.on_chain_configs).await;
            },
            (peer, backoff) = scheduled_broadcasts.select_next_some() => {
                tasks::execute_broadcast(peer, backoff, &mut smp, &mut scheduled_broadcasts, executor.clone()).await;
            },
            (network_id, event) = events.select_next_some() => {
                handle_network_event(&bounded_executor, &mut smp, network_id, event).await;
            },
            _ = update_peers_interval.tick().fuse() => {
                handle_update_peers(peers_and_metadata.clone(), &mut smp, &mut scheduled_broadcasts, executor.clone()).await;
            },
            complete => break,
        }
    }
```

**File:** mempool/src/shared_mempool/coordinator.rs (L332-341)
```rust
    bounded_executor
        .spawn(tasks::process_transaction_broadcast(
            smp_clone,
            transactions,
            message_id,
            timeline_state,
            peer,
            task_start_timer,
        ))
        .await;
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

**File:** mempool/src/shared_mempool/tasks.rs (L328-350)
```rust
    let start_storage_read = Instant::now();
    let state_view = smp
        .db
        .latest_state_checkpoint_view()
        .expect("Failed to get latest state checkpoint view.");

    // Track latency: fetching seq number
    let account_seq_numbers = IO_POOL.install(|| {
        transactions
            .par_iter()
            .map(|(t, _, _)| match t.replay_protector() {
                ReplayProtector::Nonce(_) => Ok(None),
                ReplayProtector::SequenceNumber(_) => {
                    get_account_sequence_number(&state_view, t.sender())
                        .map(Some)
                        .inspect_err(|e| {
                            error!(LogSchema::new(LogEntry::DBError).error(e));
                            counters::DB_ERROR.inc();
                        })
                },
            })
            .collect::<Vec<_>>()
    });
```

**File:** mempool/src/shared_mempool/tasks.rs (L486-504)
```rust
    // Track latency: VM validation
    let vm_validation_timer = counters::PROCESS_TXN_BREAKDOWN_LATENCY
        .with_label_values(&[counters::VM_VALIDATION_LABEL])
        .start_timer();
    let validation_results = VALIDATION_POOL.install(|| {
        transactions
            .par_iter()
            .map(|t| {
                let result = smp.validator.read().validate_transaction(t.0.clone());
                // Pre-compute the hash and length if the transaction is valid, before locking mempool
                if result.is_ok() {
                    t.0.committed_hash();
                    t.0.txn_bytes_len();
                }
                result
            })
            .collect::<Vec<_>>()
    });
    vm_validation_timer.stop_and_record();
```
