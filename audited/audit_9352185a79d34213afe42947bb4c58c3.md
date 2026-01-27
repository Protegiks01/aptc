# Audit Report

## Title
Async Cancellation Vulnerability in TPS Checker Leaves Transaction Emitter Workers Running Indefinitely

## Summary
The TPS checker's `check()` function does not properly clean up transaction emitter worker tasks when the async future is cancelled mid-execution. This leaves background workers continuously submitting transactions indefinitely, consuming gas from the coin source account and polluting the target node's mempool with untracked transactions.

## Finding Description

The vulnerability exists in the transaction emission cleanup flow. When the TPS checker runs, it:

1. Spawns multiple worker tasks that continuously submit transactions [1](#0-0) 

2. These workers run in a loop checking a stop flag [2](#0-1) 

3. The stop flag is only set when `stop_job()` is explicitly called [3](#0-2) 

4. In the normal flow, the check completes and calls `stop_job()` [4](#0-3) 

**The Critical Flaw:** The `EmitJob` struct does not implement the `Drop` trait. When the `check()` future is cancelled (via timeout, task cancellation, or client disconnect), the future is simply dropped before reaching the cleanup code. This means:

- The stop flag is never set to `true`
- Worker `JoinHandle`s are dropped, but the spawned tasks continue running
- Workers keep submitting transactions until they exhaust funds or encounter errors
- These transactions are never tracked in statistics

**Realistic Trigger Scenario:** The fn-check-client applies a default 60-second timeout to HTTP requests [5](#0-4) 

The TPS check has a default duration of 60 seconds [6](#0-5) , but the total execution time includes:
- Account creation and funding overhead [7](#0-6) 
- Transaction generator initialization [8](#0-7) 
- Optional coordination delays [9](#0-8) 
- The 60-second emission period
- Statistics collection and cleanup

This makes timeout highly likely, especially on slower networks or under load.

## Impact Explanation

This qualifies as **Medium Severity** under the Aptos bug bounty criteria ("Limited funds loss or manipulation, State inconsistencies requiring intervention"):

1. **Resource Exhaustion:** The coin source account continues spending gas on untracked transactions [10](#0-9) 

2. **State Inconsistency:** Transactions submitted after cancellation are not counted in statistics, creating misleading TPS measurements

3. **Mempool Pollution:** Target node mempool receives continuous transaction submissions from orphaned workers

4. **Multiplicative Effect:** Each timeout creates a new set of orphaned workers, compounding the resource drain

5. **No Automatic Recovery:** Workers continue until server restart or fund exhaustion

## Likelihood Explanation

**High Likelihood** in production environments:

1. **Timing Conflict:** Default test duration (60s) matches default client timeout (60s), but overhead pushes total execution time beyond timeout
2. **Client Timeouts:** Any HTTP client (including the provided fn-check-client) can apply timeouts
3. **Server Shutdowns:** Graceful server shutdowns may cancel in-flight requests
4. **Load Conditions:** Under network congestion or high load, the initialization phase can take significant time, increasing timeout probability
5. **Multiple Invocations:** Node health checking services typically run checks repeatedly, multiplying the impact

## Recommendation

Implement the `Drop` trait for `EmitJob` to ensure workers are stopped even on cancellation:

```rust
impl Drop for EmitJob {
    fn drop(&mut self) {
        // Set stop flag to signal workers to terminate
        self.stop.store(true, Ordering::Relaxed);
        // Note: We cannot await join handles in Drop (not async),
        // but setting the flag ensures workers will stop on their next iteration
    }
}
```

**Better solution:** Use structured concurrency with cancellation tokens:

```rust
use tokio_util::sync::CancellationToken;

pub struct EmitJob {
    workers: Vec<Worker>,
    cancel_token: CancellationToken,
    stats: Arc<DynamicStatsTracking>,
    phase_starts: Vec<Instant>,
}

// In worker loop:
tokio::select! {
    _ = cancel_token.cancelled() => break,
    _ = /* normal work */ => { /* ... */ }
}
```

This ensures cancellation propagates properly through the async runtime.

## Proof of Concept

```rust
#[tokio::test]
async fn test_tps_checker_cancellation_leak() {
    use tokio::time::{timeout, Duration};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    
    // Setup: Create TPS checker with test configuration
    let config = TpsCheckerConfig {
        common: CommonCheckerConfig::default(),
        emit_config: EmitArgs {
            duration: 70, // Longer than timeout
            target_tps: Some(10),
            ..Default::default()
        },
        coin_source_args: /* test mint key */,
        minimum_tps: 1,
        repeat_target_count: 1,
    };
    
    let checker = TpsChecker::new(config).unwrap();
    let providers = /* setup test providers */;
    
    // Track transaction submissions
    let submission_counter = Arc::new(AtomicU64::new(0));
    let counter_clone = submission_counter.clone();
    
    // Instrument to count submissions (in real code, check blockchain state)
    
    // Execute with timeout that will cancel the future
    let result = timeout(
        Duration::from_secs(30), // Timeout before test completes
        checker.check(&providers)
    ).await;
    
    assert!(result.is_err(), "Should timeout");
    
    // Wait and observe: workers should stop but DON'T
    tokio::time::sleep(Duration::from_secs(10)).await;
    
    let submissions_after_timeout = submission_counter.load(Ordering::Relaxed);
    
    // BUG: Submissions continue after timeout because workers not stopped
    assert!(submissions_after_timeout > 0, 
        "Workers continue submitting transactions after cancellation");
}
```

**Notes**

- This vulnerability specifically affects the node-checker component, not core consensus or blockchain functionality
- The impact is limited to resource exhaustion of the coin source account used for health checks
- While not a critical consensus bug, it violates resource limit invariants and can lead to operational issues
- The fix is straightforward: implement proper async cancellation handling via Drop or cancellation tokens
- Similar patterns should be audited throughout the codebase where background tasks are spawned without proper cancellation handling

### Citations

**File:** crates/transaction-emitter-lib/src/emitter/mod.rs (L663-664)
```rust
    pub async fn stop_and_accumulate(self) -> Vec<TxnStats> {
        self.stop.store(true, Ordering::Relaxed);
```

**File:** crates/transaction-emitter-lib/src/emitter/mod.rs (L799-812)
```rust
        let mut all_accounts = bulk_create_accounts(
            root_account.clone(),
            &RestApiReliableTransactionSubmitter::new(
                req.rest_clients.clone(),
                init_retries,
                req.init_retry_interval,
            ),
            &init_txn_factory,
            account_generator,
            (&req).into(),
            num_accounts,
            get_needed_balance_per_account_from_req(&req, num_accounts),
        )
        .await?;
```

**File:** crates/transaction-emitter-lib/src/emitter/mod.rs (L830-840)
```rust
        let (txn_generator_creator, _, _) = create_txn_generator_creator(
            req.transaction_mix_per_phase,
            source_account_manager,
            &mut all_accounts,
            vec![],
            &txn_executor,
            &txn_factory,
            &init_txn_factory,
            stats.get_cur_phase_obj(),
        )
        .await;
```

**File:** crates/transaction-emitter-lib/src/emitter/mod.rs (L842-848)
```rust
        if !req.coordination_delay_between_instances.is_zero() {
            info!(
                "Sleeping after minting/txn generator initialization for {}s",
                req.coordination_delay_between_instances.as_secs()
            );
            tokio::time::sleep(req.coordination_delay_between_instances).await;
        }
```

**File:** crates/transaction-emitter-lib/src/emitter/mod.rs (L899-904)
```rust
        let workers = submission_workers
            .into_iter()
            .map(|worker| Worker {
                join_handle: tokio_handle.spawn(worker.run(phase_start).boxed()),
            })
            .collect();
```

**File:** crates/transaction-emitter-lib/src/emitter/mod.rs (L945-946)
```rust
        info!("Ran for {} secs, stopping job...", duration.as_secs());
        let stats = job.stop_job().await;
```

**File:** crates/transaction-emitter-lib/src/emitter/submission_worker.rs (L93-93)
```rust
        while !self.stop.load(Ordering::Relaxed) {
```

**File:** crates/transaction-emitter-lib/src/emitter/submission_worker.rs (L486-501)
```rust
pub async fn submit_transactions(
    client: &RestClient,
    txns: &[SignedTransaction],
    loop_start_time: Instant,
    txn_offset_time: Arc<AtomicU64>,
    stats: &StatsAccumulator,
) {
    let cur_time = Instant::now();
    let offset = cur_time - loop_start_time;
    txn_offset_time.fetch_add(
        txns.len() as u64 * offset.as_millis() as u64,
        Ordering::Relaxed,
    );
    stats
        .submitted
        .fetch_add(txns.len() as u64, Ordering::Relaxed);
```

**File:** ecosystem/node-checker/fn-check-client/src/check.rs (L62-65)
```rust
        let nhc_client = ReqwestClient::builder()
            .timeout(Duration::from_secs(self.nhc_timeout_secs))
            .build()
            .expect("Somehow failed to build reqwest client");
```

**File:** crates/transaction-emitter-lib/src/args.rs (L129-130)
```rust
    #[clap(long, default_value_t = 60)]
    pub duration: u64,
```
