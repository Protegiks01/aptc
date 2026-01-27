# Audit Report

## Title
Async Cancellation Gauge Leak in wait_transaction_by_hash() API Endpoint

## Summary
The `wait_transaction_by_hash()` function in `api/src/transactions.rs` uses manual `inc()`/`dec()` calls on `WAIT_TRANSACTION_GAUGE` around an async operation, which is vulnerable to gauge leaks when the async function is cancelled (e.g., client disconnects). This causes the monitoring gauge to become permanently incorrect.

## Finding Description
The `wait_transaction_by_hash()` function implements a long-polling endpoint that tracks active connections using a Prometheus gauge. [1](#0-0) 

The gauge is defined as tracking "Number of transactions waiting to be processed": [2](#0-1) 

The vulnerability exists because:
1. The function increments the gauge before calling an async operation
2. The async operation contains multiple `.await` points that are cancellation points in Rust's async model [3](#0-2) 
3. If the future is cancelled/dropped (client disconnect, timeout, task cancellation) after `inc()` but before `dec()`, the gauge is never decremented

The codebase already has the correct pattern for handling this: an RAII `IntGaugeGuard` that increments in constructor and decrements in Drop implementation: [4](#0-3) 

However, the API code doesn't use this pattern and is therefore vulnerable.

**Attack Scenario:**
1. Attacker sends many requests to `/transactions/wait_by_hash/:txn_hash`
2. Attacker immediately closes connections after requests start
3. If cancellation occurs during the async operation (highly likely given the polling loop), gauges leak
4. Gauge value increases indefinitely with each leaked request
5. Monitoring/alerting based on this metric becomes incorrect

## Impact Explanation
This is classified as **Low Severity** per the Aptos bug bounty program criteria because:
- It only affects monitoring/observability, not blockchain functionality
- No funds, consensus, state, or execution are impacted
- It's a non-critical implementation bug that doesn't break any critical invariants

The impact is limited to:
- Incorrect monitoring metrics leading to false alerts or masking real issues
- Operational confusion due to inaccurate gauge values
- Potential monitoring system degradation if gauge grows very large

## Likelihood Explanation
**Likelihood: High** - This will occur naturally whenever:
- Clients disconnect during long polls (common with network issues)
- Request timeouts occur
- Server restarts happen with active requests
- Load balancers close idle connections

No malicious actor is required; normal network operations will trigger this leak over time.

## Recommendation
Replace the manual `inc()`/`dec()` pattern with the existing `IntGaugeGuard` RAII pattern. The API module should either:

1. Import and use the existing `IntGaugeGuard` from consensus module
2. Create a similar guard specifically for the API module

The fix would change the code to create a guard instead of manual calls, ensuring the decrement happens even if the future is cancelled.

## Proof of Concept
```rust
// Rust test demonstrating the issue
#[tokio::test]
async fn test_gauge_leak_on_cancellation() {
    use std::sync::atomic::{AtomicI64, Ordering};
    use std::sync::Arc;
    
    let gauge_value = Arc::new(AtomicI64::new(0));
    let gauge_clone = gauge_value.clone();
    
    // Simulate the current implementation
    let task = tokio::spawn(async move {
        gauge_clone.fetch_add(1, Ordering::Relaxed); // inc()
        
        // Long async operation (simulating wait_transaction_by_hash_inner)
        tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
        
        gauge_clone.fetch_sub(1, Ordering::Relaxed); // dec()
    });
    
    // Simulate client disconnect by aborting the task
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    task.abort();
    
    // Wait for abort to complete
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    
    // Gauge is now leaked - should be 0 but is 1
    assert_eq!(gauge_value.load(Ordering::Relaxed), 1, "Gauge leaked!");
}
```

## Notes
While this is a valid implementation bug that should be fixed, it **does not meet the validation criteria** for reporting under the Aptos bug bounty program because:
- It's explicitly Low severity (not Critical, High, or Medium as required)
- It doesn't break any of the 10 critical blockchain invariants
- It doesn't demonstrate security harm to funds, consensus, or availability
- It's purely an operational/monitoring issue

The issue should be fixed as part of regular code quality improvements, but it's not a security vulnerability in the traditional sense.

### Citations

**File:** api/src/transactions.rs (L262-273)
```rust
        WAIT_TRANSACTION_GAUGE.inc();

        let result = self
            .wait_transaction_by_hash_inner(
                &accept_type,
                txn_hash.0,
                self.context.node_config.api.wait_by_hash_timeout_ms,
                self.context.node_config.api.wait_by_hash_poll_interval_ms,
            )
            .await;

        WAIT_TRANSACTION_GAUGE.dec();
```

**File:** api/src/transactions.rs (L893-940)
```rust
    async fn wait_transaction_by_hash_inner(
        &self,
        accept_type: &AcceptType,
        hash: HashValue,
        wait_by_hash_timeout_ms: u64,
        wait_by_hash_poll_interval_ms: u64,
    ) -> BasicResultWith404<Transaction> {
        let start_time = std::time::Instant::now();
        loop {
            let context = self.context.clone();
            let accept_type = accept_type.clone();

            let (internal_ledger_info_opt, storage_ledger_info) =
                api_spawn_blocking(move || context.get_latest_internal_and_storage_ledger_info())
                    .await?;
            let storage_version = storage_ledger_info.ledger_version.into();
            let internal_ledger_version = internal_ledger_info_opt
                .as_ref()
                .map(|info| info.ledger_version.into());
            let latest_ledger_info = internal_ledger_info_opt.unwrap_or(storage_ledger_info);
            let txn_data = self
                .get_by_hash(hash.into(), storage_version, internal_ledger_version)
                .await
                .context(format!("Failed to get transaction by hash {}", hash))
                .map_err(|err| {
                    BasicErrorWith404::internal_with_code(
                        err,
                        AptosErrorCode::InternalError,
                        &latest_ledger_info,
                    )
                })?
                .context(format!("Failed to find transaction with hash: {}", hash))
                .map_err(|_| transaction_not_found_by_hash(hash, &latest_ledger_info))?;

            if matches!(txn_data, TransactionData::Pending(_))
                && (start_time.elapsed().as_millis() as u64) < wait_by_hash_timeout_ms
            {
                tokio::time::sleep(Duration::from_millis(wait_by_hash_poll_interval_ms)).await;
                continue;
            }

            let api = self.clone();
            return api_spawn_blocking(move || {
                api.get_transaction_inner(&accept_type, txn_data, &latest_ledger_info)
            })
            .await;
        }
    }
```

**File:** api/src/metrics.rs (L90-96)
```rust
pub static WAIT_TRANSACTION_GAUGE: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "aptos_api_wait_transaction",
        "Number of transactions waiting to be processed"
    )
    .unwrap()
});
```

**File:** consensus/src/lib.rs (L73-88)
```rust
pub struct IntGaugeGuard {
    gauge: IntGauge,
}

impl IntGaugeGuard {
    fn new(gauge: IntGauge) -> Self {
        gauge.inc();
        Self { gauge }
    }
}

impl Drop for IntGaugeGuard {
    fn drop(&mut self) {
        self.gauge.dec();
    }
}
```
