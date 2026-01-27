# Audit Report

## Title
Faucet Service Crash on Metric Registration Failure - Deferred Panic During First Error Response

## Summary
The Aptos faucet service uses `.unwrap()` on Prometheus metric registration calls within `Lazy` statics. If metric registration fails (e.g., due to name collision or invalid configuration), the faucet will panic and crash - but critically, **not during initialization**. The crash is deferred until the first error response is generated, when the `REJECTION_REASONS` metric is first accessed.

## Finding Description

The faucet metrics are defined as `Lazy` statics that call `.unwrap()` on metric registration: [1](#0-0) 

These lazy statics are only initialized upon first access. For `REJECTION_REASONS`, this occurs when `bump_rejection_reason_counters()` is called: [2](#0-1) 

This function is invoked when converting an `AptosTapError` to an error response: [3](#0-2) 

**Attack Path:**

While this is not directly exploitable by external attackers, it creates operational vulnerabilities:

1. Faucet starts successfully and appears healthy
2. First rejected request triggers error handling
3. `REJECTION_REASONS` lazy static initializes
4. Metric registration fails (name collision, invalid config)
5. `.unwrap()` panics, crashing the faucet thread/process
6. Faucet becomes unavailable

**Why This Matters:**

The faucet appears operational during startup but crashes unexpectedly during runtime when handling its first error condition. This is **worse** than crashing during initialization because:
- No early warning of misconfiguration
- Unexpected downtime during operation
- Difficult to diagnose (crash occurs away from the problematic configuration)

Other components like node-resource-metrics handle this gracefully: [4](#0-3) 

## Impact Explanation

**Severity: Medium**

According to the Aptos bug bounty criteria, this qualifies as Medium severity due to:

- **API Crashes**: The faucet API will crash when metric registration fails, though this would typically be classified as High severity ("API crashes")
- However, the faucet is **not critical blockchain infrastructure** - it doesn't affect:
  - Consensus safety or liveness
  - Validator operations  
  - Real fund security
  - Network availability

The impact is limited to **faucet service availability**, which is a convenience service for testnet/devnet token distribution, not core blockchain functionality.

## Likelihood Explanation

**Likelihood: Low to Medium**

This occurs when:
- Multiple faucet instances run in the same process (testing/development)
- Metric name collision from other components
- Invalid metric configuration
- Process restart scenarios

**Important Note**: This is **not directly exploitable** by unprivileged external attackers. Attackers cannot force metric registration to fail through API calls or malicious inputs. The failure scenarios are all **operational/configuration issues**.

## Recommendation

Replace `.unwrap()` with graceful error handling for all metrics:

```rust
static REJECTION_REASONS: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "aptos_tap_rejection_reason_count",
        "Number of times the tap has returned the given rejection reason.",
        &["rejection_reason_code"]
    )
    .unwrap_or_else(|e| {
        warn!("Failed to register REJECTION_REASONS metric: {}", e);
        // Return a no-op counter vec or handle gracefully
        IntCounterVec::new(
            prometheus::Opts::new(
                "aptos_tap_rejection_reason_count_fallback",
                "Fallback counter"
            ),
            &["rejection_reason_code"]
        ).unwrap()
    })
});
```

Apply similar changes to all metrics in the file: [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7) 

## Proof of Concept

```rust
#[test]
fn test_metric_registration_collision_panic() {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use once_cell::sync::Lazy;

    // First registration succeeds
    static METRIC1: Lazy<IntCounterVec> = Lazy::new(|| {
        register_int_counter_vec!(
            "test_collision_metric",
            "Test metric",
            &["label"]
        )
        .unwrap()
    });

    // Access first metric to register it
    let _ = METRIC1.with_label_values(&["test"]);

    // Second registration with same name will panic on unwrap
    static METRIC2: Lazy<IntCounterVec> = Lazy::new(|| {
        register_int_counter_vec!(
            "test_collision_metric",  // Same name!
            "Test metric duplicate",
            &["label"]
        )
        .unwrap()  // This will panic with AlreadyReg error
    });

    // This will panic when Lazy initializes
    let _ = METRIC2.with_label_values(&["test"]);
}
```

**Notes:**

While this issue exists in the codebase, it fails the critical validation criterion: **"Exploitable by unprivileged attacker (no validator insider access required)"**. This is an operational robustness issue rather than an exploitable security vulnerability. External attackers cannot trigger metric registration failures through API calls or malicious inputs. The issue only manifests under operational misconfigurations or development scenarios.

For a production security audit, this would be classified as a **code quality/robustness improvement** rather than an exploitable vulnerability warranting bug bounty payout.

### Citations

**File:** crates/aptos-faucet/core/src/middleware/metrics.rs (L11-18)
```rust
pub static HISTOGRAM: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "aptos_tap_requests",
        "Tap requests latency grouped by method, operation_id and status.",
        &["method", "operation_id", "status"]
    )
    .unwrap()
});
```

**File:** crates/aptos-faucet/core/src/middleware/metrics.rs (L20-27)
```rust
pub static RESPONSE_STATUS: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "aptos_tap_response_status",
        "Tap requests latency grouped by status code only.",
        &["status"]
    )
    .unwrap()
});
```

**File:** crates/aptos-faucet/core/src/middleware/metrics.rs (L29-36)
```rust
static REJECTION_REASONS: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "aptos_tap_rejection_reason_count",
        "Number of times the tap has returned the given rejection reason.",
        &["rejection_reason_code"]
    )
    .unwrap()
});
```

**File:** crates/aptos-faucet/core/src/middleware/metrics.rs (L38-44)
```rust
pub static NUM_OUTSTANDING_TRANSACTIONS: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "aptos_tap_num_outstanding_transactions",
        "Number of transactions we've submitted but have not been processed by the blockchain.",
    )
    .unwrap()
});
```

**File:** crates/aptos-faucet/core/src/middleware/metrics.rs (L47-53)
```rust
pub static TRANSFER_FUNDER_ACCOUNT_BALANCE: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "aptos_tap_transfer_funder_account_balance",
        "Balance of the account used by the tap instance. Only populated for the TransferFunder.",
    )
    .unwrap()
});
```

**File:** crates/aptos-faucet/core/src/middleware/metrics.rs (L55-61)
```rust
pub fn bump_rejection_reason_counters(rejection_reasons: &[RejectionReason]) {
    for rejection_reason in rejection_reasons {
        REJECTION_REASONS
            .with_label_values(&[&format!("{}", rejection_reason.get_code() as u32)])
            .inc();
    }
}
```

**File:** crates/aptos-faucet/core/src/endpoints/errors.rs (L100-109)
```rust
impl From<AptosTapError> for AptosTapErrorResponse {
    fn from(error: AptosTapError) -> Self {
        // We use this opportunity to bump metrics based on the specifics of
        // this response, since this function is only called right when we're
        // about to return this error to the client.
        bump_rejection_reason_counters(&error.rejection_reasons);
        let (status, retry_after) = error.status_and_retry_after();
        Self::Default(status, Json(error), retry_after)
    }
}
```

**File:** crates/node-resource-metrics/src/lib.rs (L45-50)
```rust
pub fn register_collector(c: Box<dyn Collector>) {
    // If not okay, then log the error and continue.
    prometheus::register(c).unwrap_or_else(|e| {
        warn!("Failed to register collector: {}", e);
    });
}
```
