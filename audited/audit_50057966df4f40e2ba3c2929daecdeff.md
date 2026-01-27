# Audit Report

## Title
API Transaction Submission Hangs Indefinitely Without Timeout When Mempool Becomes Unresponsive

## Summary
The `submit_transaction()` function in the API layer awaits a callback from mempool without any timeout mechanism. If mempool fails to respond due to bounded executor saturation or processing delays, API requests hang indefinitely until external infrastructure timeouts trigger, leading to resource exhaustion and API unavailability.

## Finding Description

The transaction submission flow lacks application-level timeout protection: [1](#0-0) 

The API creates a oneshot channel and awaits the callback response indefinitely. The mempool processes this request using a bounded executor with limited concurrent task slots: [2](#0-1) 

The bounded executor configuration limits concurrent transaction processing: [3](#0-2) 

With only 4-16 concurrent task slots (configured via `shared_mempool_max_concurrent_inbound_syncs`), the executor can saturate under load. When all slots are occupied, additional requests block waiting for permits: [4](#0-3) 

The `acquire_permit().await` call at line 50 blocks indefinitely until a permit becomes available. During this time, the API's callback is never sent, causing the API request to hang.

**Attack Scenario:**
1. Attacker submits transactions requiring extensive validation or targeting accounts with slow DB access
2. These transactions occupy all bounded executor slots (4-16 concurrent tasks)
3. Each task performs potentially slow operations including DB reads, VM validation, and mempool lock acquisition: [5](#0-4) [6](#0-5) 

4. Legitimate users' transaction submissions block indefinitely waiting for executor permits
5. API becomes unresponsive for all transaction submission requests

This breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits" - API operations should have time limits.

## Impact Explanation

**High Severity** per Aptos bug bounty criteria: "API crashes" and "Validator node slowdowns"

The vulnerability enables:
- **API Unavailability**: Transaction submission endpoint becomes unresponsive
- **Resource Exhaustion**: Blocked API requests consume goroutines, memory, and connection resources
- **Denial of Service**: Legitimate users cannot submit transactions
- **Cascading Failures**: If the API shares resources with other services, the hang can propagate

While external timeouts (HAProxy shows 60s timeout) provide eventual relief, the lack of application-level timeout means:
- Different deployments may have different timeout behaviors
- Resources are wasted during the hang period
- No graceful degradation or error reporting to clients

## Likelihood Explanation

**Medium Likelihood** - Requires specific conditions but is realistically exploitable:

**Trigger Conditions:**
- High transaction submission rate (>4-16 concurrent submissions)
- Slow transaction processing (DB performance issues, complex validation, mempool contention)
- Network conditions causing delayed processing

**Attacker Requirements:**
- Ability to submit transactions via public API (no special privileges)
- Knowledge of how to craft transactions that take longer to process

**Realistic Scenarios:**
- Network under heavy load (legitimate or attack traffic)
- Database performance degradation
- Mempool lock contention during high-throughput periods
- Combination of legitimate traffic and attacker-submitted slow transactions

The bounded executor's small capacity (4-16 slots) makes saturation feasible under realistic conditions.

## Recommendation

Implement application-level timeout for mempool callbacks using `tokio::time::timeout`:

```rust
pub async fn submit_transaction(&self, txn: SignedTransaction) -> Result<SubmissionStatus> {
    let (req_sender, callback) = oneshot::channel();
    self.mp_sender
        .clone()
        .send(MempoolClientRequest::SubmitTransaction(txn, req_sender))
        .await?;

    // Add timeout (e.g., 30 seconds)
    let timeout_duration = Duration::from_secs(30);
    match tokio::time::timeout(timeout_duration, callback).await {
        Ok(result) => result.map_err(anyhow::Error::from),
        Err(_) => Err(anyhow::anyhow!("Transaction submission timed out")),
    }
}
```

**Additional Recommendations:**
1. Make timeout duration configurable via `ApiConfig`
2. Add similar timeout to `get_pending_transaction_by_hash()`: [7](#0-6) 

3. Add metrics tracking timeout occurrences
4. Consider increasing bounded executor capacity or implementing adaptive sizing
5. Add circuit breaker pattern to fail fast when mempool is overloaded

## Proof of Concept

```rust
// Test demonstrating the hang (conceptual - would need full test harness)
#[tokio::test]
async fn test_submit_transaction_timeout() {
    use std::sync::Arc;
    use tokio::sync::mpsc;
    use futures::channel::oneshot;
    
    // Setup: Create context with mempool sender that never responds
    let (mp_sender, mut mp_receiver) = mpsc::channel(100);
    // ... initialize context with mp_sender
    
    // Spawn task that receives but never processes requests
    tokio::spawn(async move {
        while let Some(_request) = mp_receiver.recv().await {
            // Never send callback - simulates hung mempool
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
    });
    
    // Submit transaction - this will hang without timeout
    let txn = create_test_transaction();
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        context.submit_transaction(txn)
    ).await;
    
    // Without the fix, this times out at the test level
    // With the fix, it returns an error gracefully
    assert!(result.is_err(), "Should timeout");
}

// To reproduce in practice:
// 1. Submit 16+ transactions simultaneously to saturate bounded executor
// 2. Use transactions that target accounts requiring slow DB lookups
// 3. Additional submissions will hang until external timeout (60s HAProxy)
// 4. Monitor API response times and observe indefinite hangs
```

**Notes**

This vulnerability demonstrates a common anti-pattern in distributed systems: awaiting external responses without timeout protection. While infrastructure-level timeouts (HAProxy: 60s) provide eventual mitigation, best practices require application-level timeouts for:
- Predictable behavior across deployments
- Graceful error handling
- Resource management
- Observable failure modes

The bounded executor's small capacity (4-16 slots) combined with potentially slow transaction processing operations makes this vulnerability realistic under production load conditions.

### Citations

**File:** api/src/context.rs (L217-225)
```rust
    pub async fn submit_transaction(&self, txn: SignedTransaction) -> Result<SubmissionStatus> {
        let (req_sender, callback) = oneshot::channel();
        self.mp_sender
            .clone()
            .send(MempoolClientRequest::SubmitTransaction(txn, req_sender))
            .await?;

        callback.await?
    }
```

**File:** api/src/context.rs (L977-990)
```rust
    pub async fn get_pending_transaction_by_hash(
        &self,
        hash: HashValue,
    ) -> Result<Option<SignedTransaction>> {
        let (req_sender, callback) = oneshot::channel();

        self.mp_sender
            .clone()
            .send(MempoolClientRequest::GetTransactionByHash(hash, req_sender))
            .await
            .map_err(anyhow::Error::from)?;

        callback.await.map_err(anyhow::Error::from)
    }
```

**File:** mempool/src/shared_mempool/coordinator.rs (L90-93)
```rust
    // Use a BoundedExecutor to restrict only `workers_available` concurrent
    // worker tasks that can process incoming transactions.
    let workers_available = smp.config.shared_mempool_max_concurrent_inbound_syncs;
    let bounded_executor = BoundedExecutor::new(workers_available, executor.clone());
```

**File:** mempool/src/shared_mempool/coordinator.rs (L166-196)
```rust
async fn handle_client_request<NetworkClient, TransactionValidator>(
    smp: &mut SharedMempool<NetworkClient, TransactionValidator>,
    bounded_executor: &BoundedExecutor,
    request: MempoolClientRequest,
) where
    NetworkClient: NetworkClientInterface<MempoolSyncMsg> + 'static,
    TransactionValidator: TransactionValidation + 'static,
{
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

**File:** mempool/src/shared_mempool/tasks.rs (L329-350)
```rust
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

**File:** mempool/src/shared_mempool/tasks.rs (L490-506)
```rust
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
    {
        let mut mempool = smp.mempool.lock();
```
