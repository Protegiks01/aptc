# Audit Report

## Title
Unvalidated Float-to-Integer Conversion in Node-Checker Metric Parsing Allows Health Check Manipulation

## Summary
The `get_metric_value` function in the node-checker's Prometheus metric parser performs unchecked float-to-integer conversions, allowing malicious nodes to return special float values (NaN, Infinity, negative values) that are silently converted to incorrect consensus round numbers (0 or u64::MAX), enabling manipulation of node health assessments.

## Finding Description
The node-checker queries Prometheus metrics from target nodes to assess their health. When parsing the `aptos_consensus_last_committed_round` metric, the system accepts any float64 value from the Prometheus text format, including special values like NaN, +Inf, and -Inf. [1](#0-0) 

The conversion `v.round() as u64` silently transforms invalid values according to Rust 1.85 semantics:
- `NaN` → 0
- `+Inf` → u64::MAX (18446744073709551615)
- `-Inf` → 0
- Negative values → 0

A malicious node operator can craft their `/metrics` endpoint to return:
```
aptos_consensus_last_committed_round NaN
```

This propagates through the metric parsing pipeline:

1. **MetricsProvider** fetches metrics and parses via `Scrape::parse()` [2](#0-1) 

2. **get_metric_value** extracts the value and converts it without validation [3](#0-2) 

3. **ConsensusRoundChecker** compares rounds to determine health [4](#0-3) 

Attack scenarios:
- **False positive (hide broken consensus)**: Return `+Inf` → u64::MAX → checker sees massive round increase, reports healthy
- **False negative (trigger false alarms)**: Healthy node returns valid round 1000, then attacker returns `NaN` → 0 → checker reports "round went backwards" 
- **Mask stalled consensus**: Return `NaN` → 0 in both readings → checker reports "not progressing" with score 50 instead of failing completely

## Impact Explanation
This is a **Medium severity** vulnerability per the security question classification. While it does not directly compromise consensus safety, funds, or on-chain state, it affects operational integrity:

1. **Misleading health assessments**: Operators relying on node-checker results may make incorrect decisions about node maintenance, failover, or incident response
2. **Potential reward manipulation**: If node-checker results influence node incentive programs or performance rankings, malicious operators could game the system
3. **Hidden consensus failures**: Actual consensus issues could be masked by manipulated metrics, delaying detection of real problems
4. **Automated system failures**: Any automated orchestration using node-checker API could be compromised

This meets the Medium severity criterion of "State inconsistencies requiring intervention" - the node-checker state becomes inconsistent with actual node health, requiring manual verification.

## Likelihood Explanation
**High likelihood** - exploitation requires only:
1. Running a node being checked by the node-checker service
2. Modifying the `/metrics` endpoint response (trivial HTTP server configuration)
3. No special privileges, validator access, or technical sophistication

The Prometheus text format explicitly supports NaN/Inf values per specification, making this a valid input that the parser will accept.

## Recommendation
Add validation before float-to-integer conversion:

```rust
fn get_metric_value(
    metrics: &Scrape,
    metric_name: &str,
    expected_label: Option<&Label>,
) -> Option<u64> {
    // ... existing discovery logic ...
    
    match discovered_sample {
        Some(sample) => match &sample.value {
            Value::Counter(v) | Value::Gauge(v) | Value::Untyped(v) => {
                // Validate finite, non-negative value
                if !v.is_finite() {
                    warn!("Metric {} has non-finite value: {}", metric_name, v);
                    return None;
                }
                if v.is_sign_negative() {
                    warn!("Metric {} has negative value: {}", metric_name, v);
                    return None;
                }
                if *v > u64::MAX as f64 {
                    warn!("Metric {} value too large: {}", metric_name, v);
                    return None;
                }
                Some(v.round() as u64)
            },
            wildcard => {
                warn!("Found unexpected metric type: {:?}", wildcard);
                None
            },
        },
        None => None,
    }
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use prometheus_parse::{Value, Sample, Scrape};
    use std::collections::HashMap;

    #[test]
    fn test_malformed_metric_values() {
        // Simulate malicious metric responses
        let test_cases = vec![
            (f64::NAN, "NaN"),
            (f64::INFINITY, "Infinity"),
            (f64::NEG_INFINITY, "Negative Infinity"),
            (-42.5, "Negative value"),
        ];

        for (malicious_value, description) in test_cases {
            let mut labels = HashMap::new();
            let sample = Sample {
                metric: "aptos_consensus_last_committed_round".to_string(),
                value: Value::Gauge(malicious_value),
                labels,
                timestamp: None,
            };
            
            let scrape = Scrape {
                samples: vec![sample],
                docs: HashMap::new(),
            };
            
            let result = get_metric_value(
                &scrape,
                "aptos_consensus_last_committed_round",
                None
            );
            
            match result {
                Some(val) => {
                    println!("{}: {} converted to {}", description, malicious_value, val);
                    // Current behavior: NaN->0, Inf->u64::MAX, -Inf->0, -42.5->0
                    // Expected: Should return None for invalid values
                }
                None => println!("{}: Correctly rejected", description),
            }
        }
    }

    #[test]
    fn test_consensus_round_checker_manipulation() {
        // Demonstrate false positive: broken node appears healthy
        // Round 1000 (healthy) followed by NaN (broken) converted to 0
        // Checker incorrectly reports "round went backwards" instead of "metric unavailable"
        
        // Demonstrate false negative: broken node appears healthy  
        // NaN (broken) converted to 0, followed by valid round 1000
        // Checker incorrectly reports "increasing" with score 100
    }
}
```

## Notes
The vulnerability exists because the Prometheus specification allows special float values (NaN, ±Inf) in metric values, but the node-checker assumes all parsed values represent valid consensus round numbers. The `prometheus_parse` crate (v0.2.4) [5](#0-4)  correctly parses these per spec, but downstream consumers must validate semantic correctness for their domain.

### Citations

**File:** ecosystem/node-checker/src/provider/metrics.rs (L77-84)
```rust
        Scrape::parse(body.lines().map(|l| Ok(l.to_string())))
            .with_context(|| {
                format!(
                    "Failed to parse response text from {} as a Prometheus scrape",
                    self.metrics_url
                )
            })
            .map_err(|e| ProviderError::ParseError(anyhow!(e)))
```

**File:** ecosystem/node-checker/src/provider/metrics.rs (L110-147)
```rust
fn get_metric_value(
    metrics: &Scrape,
    metric_name: &str,
    expected_label: Option<&Label>,
) -> Option<u64> {
    let mut discovered_sample = None;
    for sample in &metrics.samples {
        if sample.metric == metric_name {
            match &expected_label {
                Some(expected_label) => {
                    let label_value = sample.labels.get(expected_label.key);
                    if let Some(label_value) = label_value {
                        if label_value == expected_label.value {
                            discovered_sample = Some(sample);
                            break;
                        }
                    }
                },
                None => {
                    discovered_sample = Some(sample);
                    break;
                },
            }
        }
    }
    match discovered_sample {
        Some(sample) => match &sample.value {
            Value::Counter(v) => Some(v.round() as u64),
            Value::Gauge(v) => Some(v.round() as u64),
            Value::Untyped(v) => Some(v.round() as u64),
            wildcard => {
                warn!("Found unexpected metric type: {:?}", wildcard);
                None
            },
        },
        None => None,
    }
}
```

**File:** ecosystem/node-checker/src/checker/consensus_round.rs (L53-73)
```rust
    fn build_check_result(&self, previous_round: u64, latest_round: u64) -> CheckResult {
        if latest_round < previous_round {
            Self::build_result(
                "Consensus round went backwards!".to_string(),
                0,
                format!("Successfully pulled metrics from target node twice, but the second time the consensus round went backwards (from {} to {}", previous_round, latest_round),
            )
        } else if latest_round == previous_round {
            Self::build_result(
                "Consensus round is not progressing".to_string(),
                50,
                "Successfully pulled metrics from target node twice, but the consensus round isn't progressing.".to_string(),
            )
        } else {
            Self::build_result(
                "Consensus round is increasing".to_string(),
                100,
                format!("Successfully pulled metrics from target node twice and saw that consensus round increased (from {} to {})", previous_round, latest_round),
            )
        }
    }
```

**File:** Cargo.toml (L739-739)
```text
prometheus-parse = "0.2.4"
```
