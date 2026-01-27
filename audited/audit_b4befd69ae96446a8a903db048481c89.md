# Audit Report

## Title
Transaction-Specific Data Leakage Through Unauthenticated Prometheus Metrics Endpoint

## Summary
The Aptos executor exposes transaction-specific data (module names, function names, and event creation numbers) through Prometheus metrics when the `processed_transactions_detailed_counters` configuration option is enabled. These metrics are accessible without authentication via the `/metrics` endpoint on port 9101, allowing any attacker with network access to scrape detailed information about private contract interactions and validator transaction processing patterns.

## Finding Description
The vulnerability exists in the transaction metrics collection system that tracks processed transactions by module and function name. When `processed_transactions_detailed_counters` is enabled in the node configuration, the system exposes sensitive transaction data through labeled Prometheus metrics. [1](#0-0) 

The critical data exposure occurs in the `update_counters_for_processed_chunk` function where transaction-specific information is recorded as metric labels: [2](#0-1) 

For core framework modules, even more granular data is exposed including both module AND function names: [3](#0-2) 

This configuration flag is controlled through the execution config: [4](#0-3) 

While disabled by default, it can be enabled through configuration: [5](#0-4) 

The metrics are exposed without authentication through the inspection service: [6](#0-5) [7](#0-6) 

The inspection service binds to `0.0.0.0` by default, making it accessible from any network interface: [8](#0-7) 

## Impact Explanation
This vulnerability qualifies as **Medium severity** under the Aptos bug bounty program criteria for the following reasons:

1. **Privacy Violation**: Attackers can identify which specific Move modules and functions are being executed by validators, potentially de-anonymizing user transactions when correlated with on-chain data.

2. **Validator Behavior Analysis**: Attackers can monitor transaction processing patterns to identify optimal timing for targeted attacks or network disruptions.

3. **Competitive Intelligence**: Exposure of module names reveals which smart contracts are gaining adoption before this information becomes publicly obvious on-chain.

4. **Attack Surface Mapping**: Knowledge of frequently called functions helps attackers identify high-value targets for finding and exploiting vulnerabilities.

While this is primarily information disclosure, it violates user privacy expectations and can facilitate more serious attacks, placing it above "minor information leaks" (Low severity) but below direct fund loss or consensus violations.

## Likelihood Explanation
The likelihood is **MEDIUM** because:

1. **Configuration Required**: The vulnerability requires operators to explicitly enable `processed_transactions_detailed_counters` in their node configuration, which is disabled by default.

2. **Common Practice**: Many node operators enable detailed metrics for debugging and monitoring purposes, especially in non-production or monitoring-focused deployments.

3. **Network Accessibility**: The inspection service typically requires network-level access control (firewalls), but misconfigured deployments or compromised network perimeters could expose the endpoint.

4. **No Authentication**: Once network access is gained, no additional authentication is required to scrape the metrics.

5. **Persistent Exposure**: Once enabled, the exposure is continuous and automatically updates with every processed transaction.

## Recommendation
Implement the following mitigations:

1. **Remove detailed labels from metrics** - Instead of using actual module/function names, use categorical labels like "user_module" vs "core_module":

```rust
PROCESSED_USER_TXNS_ENTRY_FUNCTION_BY_MODULE
    .with_label_values(&[
        detailed_counters_label,
        process_type,
        if is_core { "core" } else { "user" },
        // Remove this: function.module().name().as_str()
        if is_core { "core_module" } else { "user_module" },
        state,
    ])
    .inc();
```

2. **Add authentication to the inspection service** - Implement bearer token or certificate-based authentication for the `/metrics` endpoint, similar to other sensitive endpoints.

3. **Audit flag defaults** - Consider whether `processed_transactions_detailed_counters` should ever be enabled in production, or restrict it to test networks only through configuration validation.

4. **Network isolation** - Update documentation to explicitly warn operators about binding the inspection service to localhost only (`127.0.0.1`) rather than all interfaces (`0.0.0.0`).

## Proof of Concept

**Setup:**
1. Configure an Aptos validator node with detailed counters enabled:
```yaml
execution:
  processed_transactions_detailed_counters: true

inspection_service:
  address: "0.0.0.0"
  port: 9101
```

2. Start the node and wait for transaction processing.

**Exploitation:**
```bash
# Scrape metrics endpoint without authentication
curl http://<validator_ip>:9101/metrics | grep "aptos_processed_user_transactions_entry_function"

# Example output revealing module names:
# aptos_processed_user_transactions_entry_function_by_module{is_detailed="true",process="vm",account="core",name="coin",state="keep_success"} 145
# aptos_processed_user_transactions_entry_function_by_module{is_detailed="true",process="vm",account="user",name="my_private_swap_contract",state="keep_success"} 23
# aptos_processed_user_transactions_entry_function_by_core_method{process="vm",module="coin",method="transfer",state="keep_success"} 89
# aptos_processed_user_transactions_entry_function_by_core_method{process="vm",module="account",method="create_account",state="keep_success"} 12
```

**Analysis:**
The attacker can now identify:
- "my_private_swap_contract" is being used (user module exposure)
- Specific core framework functions being called with exact counts
- Transaction success rates for specific modules
- Processing patterns over time through continuous scraping

This information can be correlated with blockchain data to potentially identify specific users, target popular contracts for exploits, or plan attacks based on validator processing patterns.

## Notes

This vulnerability specifically affects the executor metrics system, not the Move VM timer metrics originally mentioned in the security question. The Move VM timer uses only static labels for performance instrumentation. However, the executor's transaction processing metrics expose the exact transaction-specific data described in the security question when detailed counters are enabled.

The fix should balance operational observability needs with privacy requirements. Consider implementing aggregated metrics that provide useful monitoring data without exposing individual module/function names, or restricting detailed metrics to internal monitoring systems with proper authentication.

### Citations

**File:** execution/executor/src/metrics.rs (L195-202)
```rust
pub static PROCESSED_USER_TXNS_ENTRY_FUNCTION_BY_MODULE: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "aptos_processed_user_transactions_entry_function_by_module",
        "Counter of processed EntryFunction user transactions by module",
        &["is_detailed", "process", "account", "name", "state"]
    )
    .unwrap()
});
```

**File:** execution/executor/src/metrics.rs (L460-474)
```rust
                PROCESSED_USER_TXNS_ENTRY_FUNCTION_BY_MODULE
                    .with_label_values(&[
                        detailed_counters_label,
                        process_type,
                        if is_core { "core" } else { "user" },
                        if detailed_counters {
                            function.module().name().as_str()
                        } else if is_core {
                            "core_module"
                        } else {
                            "user_module"
                        },
                        state,
                    ])
                    .inc();
```

**File:** execution/executor/src/metrics.rs (L476-484)
```rust
                    PROCESSED_USER_TXNS_ENTRY_FUNCTION_BY_CORE_METHOD
                        .with_label_values(&[
                            process_type,
                            function.module().name().as_str(),
                            function.function().as_str(),
                            state,
                        ])
                        .inc();
                }
```

**File:** config/src/config/execution_config.rs (L49-50)
```rust
    /// Enables enhanced metrics around processed transactions
    pub processed_transactions_detailed_counters: bool,
```

**File:** config/src/config/execution_config.rs (L89-89)
```rust
            processed_transactions_detailed_counters: false,
```

**File:** crates/aptos-inspection-service/src/server/mod.rs (L142-146)
```rust
        METRICS_PATH => {
            // /metrics
            // Exposes text encoded metrics
            metrics::handle_metrics_request()
        },
```

**File:** crates/aptos-inspection-service/src/server/metrics.rs (L72-76)
```rust
/// Handles a new metrics request (with text encoding)
pub fn handle_metrics_request() -> (StatusCode, Body, String) {
    let buffer = utils::get_encoded_metrics(TextEncoder::new());
    (StatusCode::OK, Body::from(buffer), CONTENT_TYPE_TEXT.into())
}
```

**File:** config/src/config/inspection_service_config.rs (L28-30)
```rust
        InspectionServiceConfig {
            address: "0.0.0.0".to_string(),
            port: 9101,
```
