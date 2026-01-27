# Audit Report

## Title
Division by Zero Panic in Node Health Checker Due to Missing Configuration Validation

## Summary
The `LatencyCheckerConfig` struct lacks validation to ensure `num_allowed_errors < num_samples`, allowing a misconfigured node health checker to panic with division by zero when checking a broken node that returns all errors.

## Finding Description
The `LatencyCheckerConfig` deserialization in the node health checker accepts arbitrary values for `num_allowed_errors` and `num_samples` without validating their relationship. [1](#0-0) 

When `num_allowed_errors >= num_samples`, the error threshold check becomes ineffective. The checker loops `num_samples` times and checks if `errors.len() as u16 > self.config.num_allowed_errors` after each iteration. [2](#0-1) 

If all API calls fail and `num_allowed_errors >= num_samples`, the error count never exceeds the threshold. The code then attempts to calculate average latency by dividing by `latencies.len()`, which is zero when all samples failed. [3](#0-2) 

**Exploitation path:**
1. Operator configures node-checker with `num_samples: 5` and `num_allowed_errors: 10` (or even `5`)
2. Node-checker attempts to check a broken node where all API calls fail
3. All 5 samples fail, but `5 > 10` is false, so no early return
4. Division by zero occurs at line 108: `latencies.len() as u64` equals 0

No validation exists during configuration loading [4](#0-3)  or checker construction [5](#0-4)  to prevent this scenario.

## Impact Explanation
This issue causes the node health checker service to **panic and crash** when checking nodes with the described misconfiguration. However, this is **NOT** a blockchain security vulnerability because:

1. The node-checker is an **ecosystem monitoring tool**, not part of consensus
2. It does not handle funds, affect state transitions, or participate in block production
3. The crash only affects the monitoring service, not validator nodes or the blockchain
4. This does not fall under any Critical/High/Medium severity category in the bug bounty program

While this is a real implementation bug that should be fixed, it represents a **reliability issue in tooling** rather than a security vulnerability affecting the Aptos blockchain protocol.

## Likelihood Explanation
The likelihood is **low to moderate**:
- Requires operator misconfiguration (setting `num_allowed_errors >= num_samples`)
- Default values are safe (`num_samples: 5`, `num_allowed_errors: 0`)
- No external attacker can inject this configuration
- Only affects operators who manually override the defaults incorrectly

## Recommendation
Add validation in `LatencyCheckerConfig` construction or in the `validate_configuration` function:

```rust
impl LatencyCheckerConfig {
    pub fn validate(&self) -> Result<(), anyhow::Error> {
        if self.num_allowed_errors >= self.num_samples {
            anyhow::bail!(
                "num_allowed_errors ({}) must be less than num_samples ({})",
                self.num_allowed_errors,
                self.num_samples
            );
        }
        Ok(())
    }
}
```

Call this validation in `LatencyChecker::new()` or in the configuration validation step.

## Proof of Concept
```rust
// Test case demonstrating the panic
#[tokio::test]
#[should_panic(expected = "attempt to divide by zero")]
async fn test_latency_checker_division_by_zero() {
    use crate::checker::{LatencyChecker, LatencyCheckerConfig, CommonCheckerConfig};
    
    let config = LatencyCheckerConfig {
        common: CommonCheckerConfig { required: false },
        num_samples: 5,
        num_allowed_errors: 10, // >= num_samples
        delay_between_samples_ms: 0,
        max_api_latency_ms: 1000,
    };
    
    let checker = LatencyChecker::new(config);
    
    // Mock provider that always returns errors
    // ... (provider setup omitted for brevity)
    
    // This will panic with division by zero
    let _ = checker.check(&providers).await;
}
```

---

**Note:** This finding does not meet the security vulnerability criteria outlined in the validation checklist because it affects ecosystem tooling rather than core blockchain security. It should be addressed as a code quality/reliability issue rather than a security vulnerability.

### Citations

**File:** ecosystem/node-checker/src/checker/latency.rs (L16-40)
```rust
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LatencyCheckerConfig {
    #[serde(flatten)]
    pub common: CommonCheckerConfig,

    /// The number of times to hit the node to check latency.
    #[serde(default = "LatencyCheckerConfig::default_num_samples")]
    pub num_samples: u16,

    /// The delay between each call.
    #[serde(default = "LatencyCheckerConfig::default_delay_between_samples_ms")]
    pub delay_between_samples_ms: u64,

    /// The number of responses that are allowed to be errors.
    #[serde(default)]
    pub num_allowed_errors: u16,

    /// If the average latency exceeds this value, it will fail the evaluation.
    /// This value is not the same as regular latency , e.g. with the ping tool.
    /// Instead, this measures the total RTT for an API call to the node. See
    /// https://aptos.dev/nodes/node-health-checker/node-health-checker-faq#how-does-the-latency-evaluator-work
    /// for more information.
    pub max_api_latency_ms: u64,
}
```

**File:** ecosystem/node-checker/src/checker/latency.rs (L58-60)
```rust
    pub fn new(config: LatencyCheckerConfig) -> Self {
        Self { config }
    }
```

**File:** ecosystem/node-checker/src/checker/latency.rs (L84-105)
```rust
        for _ in 0..self.config.num_samples {
            match self.get_latency_datapoint(target_api_index_provider).await {
                Ok(latency) => latencies.push(latency),
                Err(e) => errors.push(e),
            }
            if errors.len() as u16 > self.config.num_allowed_errors {
                return Ok(vec![
                    Self::build_result(
                        "Node returned too many errors while checking API latency".to_string(),
                        0,
                        format!(
                            "The node returned too many errors while checking API RTT (Round trip time), the tolerance was {} errors out of {} calls: {}. Note, this latency is not the same as standard ping latency, see the attached link.",
                            self.config.num_allowed_errors, self.config.num_samples, errors.into_iter().map(|e| e.to_string()).collect::<Vec<String>>().join(", "),
                        )
                    ).links(vec![LINK.to_string()])
                ]);
            }
            tokio::time::sleep(std::time::Duration::from_millis(
                self.config.delay_between_samples_ms,
            ))
            .await;
        }
```

**File:** ecosystem/node-checker/src/checker/latency.rs (L107-108)
```rust
        let average_latency =
            latencies.iter().sum::<Duration>().as_millis() as u64 / latencies.len() as u64;
```

**File:** ecosystem/node-checker/src/configuration/validate.rs (L24-27)
```rust
pub fn validate_configuration(node_configuration: &BaselineConfiguration) -> Result<()> {
    build_checkers(&node_configuration.checkers).context("Failed to build Checkers")?;
    Ok(())
}
```
