# Audit Report

## Title
Prometheus Cardinality Explosion via Unbounded Module Names in Transaction Metrics

## Summary
When the `processed_transactions_detailed_counters` configuration flag is enabled, user-deployed Move module names are used directly as Prometheus label values without cardinality protection. An attacker can deploy numerous modules with unique names, causing unbounded Prometheus metric cardinality that exhausts validator memory and degrades performance.

## Finding Description

The vulnerability exists in the transaction metrics collection system. When detailed counters are enabled, the system records metrics for each processed transaction, including the module name for entry function calls. [1](#0-0) 

The vulnerable code path occurs in the `update_counters_for_processed_chunk` function: [2](#0-1) 

When `detailed_counters` is enabled (line 270), the code at line 466 uses `function.module().name().as_str()` directly as a Prometheus label value for both core and user modules. Since users can deploy arbitrary Move modules with names up to 255 characters, an attacker can create unbounded label cardinality. [3](#0-2) 

The detailed counters feature is controlled by a configuration flag: [4](#0-3) 

While this feature is disabled by default, validators can enable it for enhanced monitoring: [5](#0-4) 

**Attack Path:**
1. Attacker identifies validators with `processed_transactions_detailed_counters` enabled
2. Attacker deploys multiple Move modules with unique 255-character names (constrained only by gas costs)
3. Attacker submits transactions calling entry functions in these modules
4. Each unique module name creates new Prometheus time series with labels: `[is_detailed, process_type, "user", module_name, state]`
5. Prometheus memory consumption grows linearly with the number of unique module names
6. Query performance degrades as cardinality increases
7. Validator nodes experience memory pressure and performance degradation

The Move identifier size limit is 255 bytes: [6](#0-5) 

Other parts of the codebase demonstrate proper cardinality protection by using fixed labels for unknown values, but this pattern is not applied in the executor metrics: [7](#0-6) 

## Impact Explanation

This vulnerability qualifies as **Medium Severity** under the Aptos bug bounty program's criteria: "Validator node slowdowns."

When exploited against validators with detailed counters enabled:
- **Memory Exhaustion**: Each unique module name creates new Prometheus time series, consuming memory. With thousands of unique modules, this can exhaust available memory.
- **Query Degradation**: Prometheus query performance degrades significantly with high cardinality, impacting monitoring and alerting systems.
- **CPU Impact**: Metric collection and aggregation overhead increases with cardinality.
- **Cascading Effects**: Monitoring failures can mask other security issues or operational problems.

While gas costs provide some economic barrier, the cost of deploying modules may be significantly less than the operational impact on validators, making this attack economically viable for a determined attacker.

## Likelihood Explanation

**Likelihood: Medium**

Required conditions:
1. Validator must have `processed_transactions_detailed_counters: true` in their configuration (not default)
2. Attacker must pay gas fees for module deployments and function calls
3. Attack effectiveness depends on number of validators with the feature enabled

Factors increasing likelihood:
- Validators seeking detailed metrics for performance analysis may enable this feature
- No documentation warns about cardinality risks when enabling this feature
- No runtime protection exists when the feature is enabled
- Attack is straightforward and doesn't require specialized knowledge

Factors decreasing likelihood:
- Feature is disabled by default
- Gas costs provide economic friction
- Requires sustained attack to cause significant impact

## Recommendation

Implement cardinality protection for user module names in the metrics system:

**Option 1: Use fixed labels for user modules**
```rust
if detailed_counters {
    if is_core {
        function.module().name().as_str()
    } else {
        "user_module"  // Fixed label for all user modules
    }
} else if is_core {
    "core_module"
} else {
    "user_module"
}
```

**Option 2: Implement an allowlist for tracked modules**
```rust
const TRACKED_USER_MODULES: &[&str] = &["commonly_used_module1", "commonly_used_module2"];

if detailed_counters {
    if is_core {
        function.module().name().as_str()
    } else {
        let module_name = function.module().name().as_str();
        if TRACKED_USER_MODULES.contains(&module_name) {
            module_name
        } else {
            "other_user_module"
        }
    }
} else if is_core {
    "core_module"
} else {
    "user_module"
}
```

**Option 3: Add configuration documentation**
Add prominent warnings in the configuration documentation about cardinality risks when enabling `processed_transactions_detailed_counters`.

**Recommended approach**: Implement Option 1 or 2 to eliminate the vulnerability at the source, and add documentation warnings regardless.

## Proof of Concept

```rust
// Move module deployment PoC (pseudocode)
// Deploy multiple modules with unique names

use aptos_framework::code;

// Module 1
module attacker_addr::unique_module_name_0000000001 {
    public entry fun test() {}
}

// Module 2
module attacker_addr::unique_module_name_0000000002 {
    public entry fun test() {}
}

// ... repeat for N modules with unique names up to 255 chars

// Then submit transactions calling each entry function:
// aptos move run --function-id attacker_addr::unique_module_name_0000000001::test
// aptos move run --function-id attacker_addr::unique_module_name_0000000002::test
// ...

// Monitor Prometheus metrics:
// curl http://validator:9101/metrics | grep aptos_processed_user_transactions_entry_function_by_module
// Observe cardinality growth with each unique module name
```

To reproduce:
1. Configure a local validator with `processed_transactions_detailed_counters: true`
2. Deploy 100+ Move modules with unique 255-character names to an account
3. Submit transactions calling entry functions in each module
4. Query Prometheus metrics endpoint and observe:
   - Metric cardinality increases with each unique module
   - Memory usage grows proportionally
   - Query latency increases with cardinality

Expected result: Unbounded growth in `aptos_processed_user_transactions_entry_function_by_module` metric cardinality, limited only by available gas and attacker resources.

## Notes

- The vulnerability specifically affects validators who enable the `processed_transactions_detailed_counters` feature for enhanced monitoring
- While gas costs provide economic friction, they may be insufficient to prevent attacks if the operational impact on validators is high enough
- The same pattern exists for signature type names (lines 400, 410) but those use a bounded enum, so they are not vulnerable
- Core module tracking (lines 476-483) is not vulnerable as users cannot deploy modules at the core address
- This issue represents a gap between operational monitoring needs and security considerations in metric collection

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

**File:** execution/executor/src/metrics.rs (L270-271)
```rust
    let detailed_counters = AptosVM::get_processed_transactions_detailed_counters();
    let detailed_counters_label = if detailed_counters { "true" } else { "false" };
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

**File:** config/src/config/execution_config.rs (L50-50)
```rust
    pub processed_transactions_detailed_counters: bool,
```

**File:** config/src/config/execution_config.rs (L89-89)
```rust
            processed_transactions_detailed_counters: false,
```

**File:** third_party/move/move-binary-format/src/file_format_common.rs (L67-67)
```rust
pub const IDENTIFIER_SIZE_MAX: u64 = 255;
```

**File:** keyless/pepper/service/src/metrics.rs (L37-51)
```rust
});

// Histogram for tracking time taken to fetch external resources
static EXTERNAL_RESOURCE_FETCH_SECONDS: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "keyless_pepper_service_external_resource_fetch_seconds",
        "Time taken to fetch external resources",
        &["resource", "succeeded"],
        LATENCY_BUCKETS.clone()
    )
    .unwrap()
});

// Histogram for tracking time taken to fetch JWKs by issuer and result
static JWK_FETCH_SECONDS: Lazy<HistogramVec> = Lazy::new(|| {
```
