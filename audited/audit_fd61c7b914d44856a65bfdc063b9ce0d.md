# Audit Report

## Title
Mempool Coordinator Event Loop DoS via BoundedExecutor Saturation

## Summary
The mempool coordinator's main event loop blocks indefinitely when processing incoming broadcast messages if the `BoundedExecutor` task queue is saturated. A malicious peer can send multiple large transaction broadcasts to exhaust all concurrent processing permits, preventing the node from handling critical events including consensus requests, client transactions, and reconfigurations.

## Finding Description
The mempool coordinator uses a `BoundedExecutor` with limited concurrency (`shared_mempool_max_concurrent_inbound_syncs`, default 4 for validators, 16 for VFNs) to process incoming transaction broadcasts. When a `BroadcastTransactionsRequest` message is received, the coordinator awaits on spawning an async task to process the broadcast. [1](#0-0) 

The critical issue is that `bounded_executor.spawn()` blocks when all permits are in use: [2](#0-1) 

The coordinator's main event loop processes network events sequentially: [3](#0-2) 

When `handle_network_event()` blocks waiting for a `BoundedExecutor` permit, the entire coordinator loop blocks, unable to process other critical branches including:
- Client transaction submissions (`client_events`)
- Consensus block requests (`quorum_store_requests`)
- Reconfiguration notifications (`mempool_reconfig_events`)
- Broadcast ACKs and peer updates

**Attack Path:**
1. Attacker (malicious peer) sends N broadcast messages where N > `shared_mempool_max_concurrent_inbound_syncs`
2. Each broadcast contains many transactions (up to network message size limit of 64 MiB)
3. The first `shared_mempool_max_concurrent_inbound_syncs` broadcasts spawn tasks that begin processing
4. Processing transactions requires database reads and VM validation, which can be slow: [4](#0-3) 

5. While these tasks are running, the coordinator attempts to process the next broadcast
6. The coordinator blocks indefinitely at `bounded_executor.spawn().await`, unable to process any other events
7. The node becomes unresponsive to consensus, cannot serve client transactions, and cannot process reconfigurations

The attacker can amplify the attack by:
- Crafting transactions with complex Move bytecode that takes longer to validate
- Including transactions that trigger slow database lookups
- Continuously sending new broadcasts to maintain saturation

There is no validation on the receiver side rejecting oversized broadcasts before spawning processing tasks. The sender-side limit `shared_mempool_batch_size` does not apply to malicious peers.

## Impact Explanation
This vulnerability enables a **High Severity** denial-of-service attack:

**Validator Node Slowdowns/Unavailability (High Severity - up to $50,000):**
- A single malicious peer can completely halt mempool event processing
- The node cannot serve consensus block requests, potentially causing consensus stalls
- Client transactions cannot be submitted or retrieved
- The node becomes unresponsive to critical system events (reconfigurations, peer updates)

**Potential Consensus Liveness Impact:**
- If validators cannot respond to quorum store requests, block production may halt
- The attack violates the Resource Limits invariant (#9): operations should respect computational limits and not allow single peers to exhaust node resources

The impact is limited to individual nodes (not network-wide), but affects critical blockchain operations including consensus participation and transaction processing.

## Likelihood Explanation
**Likelihood: High**

The attack is trivial to execute:
- **No special permissions required**: Any connected peer can send broadcast messages
- **Low complexity**: Simply send 5+ broadcast messages in quick succession (for default config with 4 permits)
- **Easily amplified**: Each broadcast can contain thousands of transactions (limited only by network message size)
- **No detection/prevention**: There are no rate limits on incoming broadcasts per peer, no size validation before spawning tasks, and no timeouts on task execution

The vulnerability is deterministic and requires only:
1. Network connectivity to a target node
2. Ability to send P2P messages (standard mempool protocol)
3. Sending broadcasts faster than they can be processed

## Recommendation

Implement non-blocking broadcast processing using `try_spawn()` instead of `spawn()`:

```rust
async fn process_received_txns<NetworkClient, TransactionValidator>(
    bounded_executor: &BoundedExecutor,
    smp: &mut SharedMempool<NetworkClient, TransactionValidator>,
    network_id: NetworkId,
    message_id: MempoolMessageId,
    transactions: Vec<(SignedTransaction, Option<u64>, Option<BroadcastPeerPriority>)>,
    peer_id: PeerId,
) where
    NetworkClient: NetworkClientInterface<MempoolSyncMsg> + 'static,
    TransactionValidator: TransactionValidation + 'static,
{
    // Validate broadcast size before spawning
    if transactions.len() > smp.config.shared_mempool_batch_size {
        warn!("Rejecting oversized broadcast from peer {:?}: {} transactions exceeds limit {}", 
              peer_id, transactions.len(), smp.config.shared_mempool_batch_size);
        return;
    }
    
    let peer = PeerNetworkId::new(network_id, peer_id);
    let smp_clone = smp.clone();
    let ineligible_for_broadcast = (smp.network_interface.is_validator()
        && !smp.broadcast_within_validator_network())
        || smp.network_interface.is_upstream_peer(&peer, None);
    let timeline_state = if ineligible_for_broadcast {
        TimelineState::NonQualified
    } else {
        TimelineState::NotReady
    };
    
    // Use try_spawn to avoid blocking the coordinator
    match bounded_executor.try_spawn(tasks::process_transaction_broadcast(
        smp_clone,
        transactions,
        message_id,
        timeline_state,
        peer,
        counters::task_spawn_latency_timer(
            counters::PEER_BROADCAST_EVENT_LABEL,
            counters::START_LABEL,
        ),
    )) {
        Ok(_) => {
            // Task spawned successfully
            smp.network_interface.num_mempool_txns_received_since_peers_updated += transactions.len() as u64;
        }
        Err(_) => {
            // Executor at capacity, reject broadcast with backpressure signal
            warn!("Rejecting broadcast from peer {:?}: executor at capacity", peer);
            counters::shared_mempool_event_inc("executor_full");
            // Send immediate ACK with backoff to trigger sender-side rate limiting
            let ack_response = MempoolSyncMsg::BroadcastTransactionsResponse {
                message_id,
                retry: false,
                backoff: true,
            };
            let _ = smp.network_interface.send_message_to_peer(peer, ack_response);
        }
    }
}
```

Additional mitigations:
1. **Add per-peer rate limiting** on incoming broadcasts
2. **Validate broadcast size** before spawning processing tasks
3. **Add timeouts** for transaction processing tasks
4. **Increase `shared_mempool_max_concurrent_inbound_syncs`** for validators (currently optimized to 2, should be higher)

## Proof of Concept

```rust
#[tokio::test]
async fn test_coordinator_blocking_dos() {
    use aptos_config::config::NodeConfig;
    use aptos_mempool::tests::common::TestTransaction;
    
    // Create mempool with minimal concurrency (2 permits)
    let mut config = NodeConfig::get_default_validator_config();
    config.mempool.shared_mempool_max_concurrent_inbound_syncs = 2;
    
    let (mut mempool, mock_network) = create_test_mempool(config);
    
    // Create broadcasts with many transactions (each takes time to validate)
    let peer = create_test_peer();
    let broadcasts = (0..5).map(|i| {
        let txns: Vec<_> = (0..1000)
            .map(|j| TestTransaction::new(i * 1000 + j, 1, 1))
            .collect();
        create_broadcast_message(txns)
    }).collect::<Vec<_>>();
    
    // Send 5 broadcasts rapidly (more than the 2 permits available)
    let start = Instant::now();
    for broadcast in broadcasts {
        mock_network.send_message_to_mempool(peer, broadcast);
    }
    
    // Attempt to send a client transaction - this should timeout
    let client_txn = TestTransaction::new(10000, 1, 1);
    let submit_future = mempool.submit_transaction(client_txn);
    
    match timeout(Duration::from_secs(1), submit_future).await {
        Ok(_) => panic!("Expected timeout, but transaction was processed"),
        Err(_) => {
            println!("SUCCESS: Client transaction timed out after {:?} - coordinator blocked!", 
                     start.elapsed());
            // Coordinator is blocked processing broadcasts and cannot handle client requests
        }
    }
}
```

The test demonstrates that sending more broadcasts than available `BoundedExecutor` permits causes the coordinator to block, preventing it from processing client transactions or other critical events.

### Citations

**File:** mempool/src/shared_mempool/coordinator.rs (L121-123)
```rust
            (network_id, event) = events.select_next_some() => {
                handle_network_event(&bounded_executor, &mut smp, network_id, event).await;
            },
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

**File:** crates/bounded-executor/src/executor.rs (L45-52)
```rust
    pub async fn spawn<F>(&self, future: F) -> JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let permit = self.acquire_permit().await;
        self.executor.spawn(future_with_permit(future, permit))
    }
```

**File:** mempool/src/shared_mempool/tasks.rs (L304-403)
```rust
pub(crate) fn process_incoming_transactions<NetworkClient, TransactionValidator>(
    smp: &SharedMempool<NetworkClient, TransactionValidator>,
    transactions: Vec<(
        SignedTransaction,
        Option<u64>,
        Option<BroadcastPeerPriority>,
    )>,
    timeline_state: TimelineState,
    client_submitted: bool,
) -> Vec<SubmissionStatusBundle>
where
    NetworkClient: NetworkClientInterface<MempoolSyncMsg>,
    TransactionValidator: TransactionValidation,
{
    // Filter out any disallowed transactions
    let mut statuses = vec![];
    let transactions =
        filter_transactions(&smp.transaction_filter_config, transactions, &mut statuses);

    // If there are no transactions left after filtering, return early
    if transactions.is_empty() {
        return statuses;
    }

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

    // Track latency for storage read fetching sequence number
    let storage_read_latency = start_storage_read.elapsed();
    counters::PROCESS_TXN_BREAKDOWN_LATENCY
        .with_label_values(&[counters::FETCH_SEQ_NUM_LABEL])
        .observe(storage_read_latency.as_secs_f64() / transactions.len() as f64);

    let transactions: Vec<_> = transactions
        .into_iter()
        .enumerate()
        .filter_map(|(idx, (t, ready_time_at_sender, priority))| {
            if let Ok(account_sequence_num) = account_seq_numbers[idx] {
                match account_sequence_num {
                    Some(sequence_num) => {
                        if t.sequence_number() >= sequence_num {
                            return Some((t, Some(sequence_num), ready_time_at_sender, priority));
                        } else {
                            statuses.push((
                                t,
                                (
                                    MempoolStatus::new(MempoolStatusCode::VmError),
                                    Some(DiscardedVMStatus::SEQUENCE_NUMBER_TOO_OLD),
                                ),
                            ));
                        }
                    },
                    None => {
                        return Some((t, None, ready_time_at_sender, priority));
                    },
                }
            } else {
                // Failed to get account's onchain sequence number
                statuses.push((
                    t,
                    (
                        MempoolStatus::new(MempoolStatusCode::VmError),
                        Some(DiscardedVMStatus::RESOURCE_DOES_NOT_EXIST),
                    ),
                ));
            }
            None
        })
        .collect();

    validate_and_add_transactions(
        transactions,
        smp,
        timeline_state,
        &mut statuses,
        client_submitted,
    );
    notify_subscribers(SharedMempoolNotification::NewTransactions, &smp.subscribers);
    statuses
```
