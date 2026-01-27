# Audit Report

## Title
GetTransactionByHash Request Flooding Can Temporarily Delay Transaction Submissions

## Summary
The mempool coordinator's `handle_client_request()` function processes both `GetTransactionByHash` query requests and critical `SubmitTransaction` requests through the same `BoundedExecutor` without prioritization, allowing an attacker to temporarily delay transaction submissions through request flooding.

## Finding Description

The shared mempool coordinator processes all client requests (queries and transaction submissions) through a single `BoundedExecutor` with limited capacity: [1](#0-0) 

Both `GetTransactionByHash` and `SubmitTransaction` requests compete for the same executor slots: [2](#0-1) 

The BoundedExecutor has a default capacity of only 4 concurrent tasks (16 for VFNs): [3](#0-2) [4](#0-3) 

The channel buffer is 1024 requests: [5](#0-4) [6](#0-5) 

While `GetTransactionByHash` operations are fast (just a hash lookup): [7](#0-6) 

An attacker can flood these requests to temporarily occupy executor slots and delay legitimate transaction submissions, which require significantly more processing (storage reads and VM validation): [8](#0-7) 

## Impact Explanation

This issue qualifies as **Medium severity** with limited practical impact:

- **Not Critical/High**: Does not cause permanent DoS, consensus violations, or fund loss
- **Medium severity characteristics**: Can cause temporary API service degradation and transaction submission delays
- **Mitigating factors**: GetTransactionByHash completes in microseconds, making sustained attacks difficult; channel backpressure provides natural rate limiting; most production deployments have external rate limiting

The attack would cause user experience degradation but not complete service unavailability.

## Likelihood Explanation

**Likelihood: Medium to Low**

- Attacker requirements: High request rate (thousands per second) to sustain occupation of 4-16 executor slots
- Complexity: Low (simple API flooding)
- Practical constraints: GetTransactionByHash operations complete too quickly (microseconds) to easily sustain full executor occupation; external rate limiting typically exists in production

## Recommendation

Implement separate executor pools or priority queuing for critical operations versus queries:

```rust
// Separate executors for different request types
let transaction_executor = BoundedExecutor::new(
    smp.config.shared_mempool_max_concurrent_inbound_syncs, 
    executor.clone()
);
let query_executor = BoundedExecutor::new(
    smp.config.shared_mempool_max_concurrent_inbound_syncs / 2, 
    executor.clone()
);

match request {
    MempoolClientRequest::SubmitTransaction(txn, callback) => {
        transaction_executor.spawn(/* ... */).await;
    },
    MempoolClientRequest::GetTransactionByHash(hash, callback) => {
        query_executor.spawn(/* ... */).await;
    },
    // ...
}
```

Alternatively, implement request prioritization or add dedicated rate limiting for GetTransactionByHash at the API layer.

## Proof of Concept

```rust
#[tokio::test]
async fn test_get_transaction_by_hash_flood() {
    // Setup mempool with small executor capacity
    let config = NodeConfig::default();
    config.mempool.shared_mempool_max_concurrent_inbound_syncs = 4;
    
    let (mempool_sender, mempool_receiver) = mpsc::channel(1024);
    
    // Spawn mempool coordinator
    tokio::spawn(coordinator(smp, executor, /* ... */, mempool_receiver, /* ... */));
    
    // Flood with GetTransactionByHash requests
    for _ in 0..2000 {
        let (tx, _rx) = oneshot::channel();
        mempool_sender.send(
            MempoolClientRequest::GetTransactionByHash(
                HashValue::random(), 
                tx
            )
        ).await.unwrap();
    }
    
    // Attempt to submit transaction - will be delayed
    let start = Instant::now();
    let (tx, rx) = oneshot::channel();
    mempool_sender.send(
        MempoolClientRequest::SubmitTransaction(
            create_signed_transaction(), 
            tx
        )
    ).await.unwrap();
    
    let result = rx.await.unwrap();
    let latency = start.elapsed();
    
    // Latency will be higher than normal due to queue backlog
    assert!(latency > Duration::from_millis(100));
}
```

**Notes**

While this represents a design weakness (lack of prioritization between critical and non-critical operations), the practical exploitability is limited by the extremely fast execution time of `GetTransactionByHash` operations. The vulnerability requires sustained high request rates to maintain meaningful impact, and production deployments typically have multiple layers of rate limiting that would mitigate this attack vector. The issue does not break any critical consensus or state consistency invariants, making it a service degradation concern rather than a fundamental security vulnerability.

### Citations

**File:** mempool/src/shared_mempool/coordinator.rs (L90-93)
```rust
    // Use a BoundedExecutor to restrict only `workers_available` concurrent
    // worker tasks that can process incoming transactions.
    let workers_available = smp.config.shared_mempool_max_concurrent_inbound_syncs;
    let bounded_executor = BoundedExecutor::new(workers_available, executor.clone());
```

**File:** mempool/src/shared_mempool/coordinator.rs (L174-218)
```rust
    match request {
        MempoolClientRequest::SubmitTransaction(txn, callback) => {
            // This timer measures how long it took for the bounded executor to *schedule* the
            // task.
            let _timer = counters::task_spawn_latency_timer(
                counters::CLIENT_EVENT_LABEL,
                counters::SPAWN_LABEL,
            );
            // This timer measures how long it took for the task to go from scheduled to started.
            let task_start_timer = counters::task_spawn_latency_timer(
                counters::CLIENT_EVENT_LABEL,
                counters::START_LABEL,
            );
            smp.network_interface
                .num_mempool_txns_received_since_peers_updated += 1;
            bounded_executor
                .spawn(tasks::process_client_transaction_submission(
                    smp.clone(),
                    txn,
                    callback,
                    task_start_timer,
                ))
                .await;
        },
        MempoolClientRequest::GetTransactionByHash(hash, callback) => {
            // This timer measures how long it took for the bounded executor to *schedule* the
            // task.
            let _timer = counters::task_spawn_latency_timer(
                counters::CLIENT_EVENT_GET_TXN_LABEL,
                counters::SPAWN_LABEL,
            );
            // This timer measures how long it took for the task to go from scheduled to started.
            let task_start_timer = counters::task_spawn_latency_timer(
                counters::CLIENT_EVENT_GET_TXN_LABEL,
                counters::START_LABEL,
            );
            bounded_executor
                .spawn(tasks::process_client_get_transaction(
                    smp.clone(),
                    hash,
                    callback,
                    task_start_timer,
                ))
                .await;
        },
```

**File:** config/src/config/mempool_config.rs (L116-116)
```rust
            shared_mempool_max_concurrent_inbound_syncs: 4,
```

**File:** config/src/config/mempool_config.rs (L216-219)
```rust
            // Set the shared_mempool_max_concurrent_inbound_syncs to 16 (default is 4)
            if local_mempool_config_yaml["shared_mempool_max_concurrent_inbound_syncs"].is_null() {
                mempool_config.shared_mempool_max_concurrent_inbound_syncs = 16;
                modified_config = true;
```

**File:** aptos-node/src/services.rs (L46-46)
```rust
const AC_SMP_CHANNEL_BUFFER_SIZE: usize = 1_024;
```

**File:** aptos-node/src/services.rs (L69-70)
```rust
    let (mempool_client_sender, mempool_client_receiver) =
        mpsc::channel(AC_SMP_CHANNEL_BUFFER_SIZE);
```

**File:** mempool/src/shared_mempool/tasks.rs (L128-165)
```rust
/// Processes transactions directly submitted by client.
pub(crate) async fn process_client_transaction_submission<NetworkClient, TransactionValidator>(
    smp: SharedMempool<NetworkClient, TransactionValidator>,
    transaction: SignedTransaction,
    callback: oneshot::Sender<Result<SubmissionStatus>>,
    timer: HistogramTimer,
) where
    NetworkClient: NetworkClientInterface<MempoolSyncMsg>,
    TransactionValidator: TransactionValidation + 'static,
{
    timer.stop_and_record();
    let _timer = counters::process_txn_submit_latency_timer_client();
    let ineligible_for_broadcast =
        smp.network_interface.is_validator() && !smp.broadcast_within_validator_network();
    let timeline_state = if ineligible_for_broadcast {
        TimelineState::NonQualified
    } else {
        TimelineState::NotReady
    };
    let statuses: Vec<(SignedTransaction, (MempoolStatus, Option<StatusCode>))> =
        process_incoming_transactions(
            &smp,
            vec![(transaction, None, Some(BroadcastPeerPriority::Primary))],
            timeline_state,
            true,
        );
    log_txn_process_results(&statuses, None);

    if let Some(status) = statuses.first() {
        if callback.send(Ok(status.1.clone())).is_err() {
            warn!(LogSchema::event_log(
                LogEntry::JsonRpc,
                LogEvent::CallbackFail
            ));
            counters::CLIENT_CALLBACK_FAIL.inc();
        }
    }
}
```

**File:** mempool/src/shared_mempool/tasks.rs (L186-207)
```rust
/// Processes get transaction by hash request by client.
pub(crate) async fn process_client_get_transaction<NetworkClient, TransactionValidator>(
    smp: SharedMempool<NetworkClient, TransactionValidator>,
    hash: HashValue,
    callback: oneshot::Sender<Option<SignedTransaction>>,
    timer: HistogramTimer,
) where
    NetworkClient: NetworkClientInterface<MempoolSyncMsg>,
    TransactionValidator: TransactionValidation,
{
    timer.stop_and_record();
    let _timer = counters::process_get_txn_latency_timer_client();
    let txn = smp.mempool.lock().get_by_hash(hash);

    if callback.send(txn).is_err() {
        warn!(LogSchema::event_log(
            LogEntry::GetTransaction,
            LogEvent::CallbackFail
        ));
        counters::CLIENT_CALLBACK_FAIL.inc();
    }
}
```
