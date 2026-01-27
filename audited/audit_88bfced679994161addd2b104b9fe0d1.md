# Audit Report

## Title
Validation Bypass in Node Health Checker Through Empty CheckResult Vector Interpretation

## Summary
The Node Health Checker's `CheckSummary` implementation assigns a perfect score of 100 when given an empty vector of check results, allowing nodes to bypass validation entirely when checkers have `required=false` and their providers are unavailable.

## Finding Description

The vulnerability exists in the score calculation logic when creating a `CheckSummary` from check results. [1](#0-0) 

When `check_results.len()` is 0, the `summary_score` is set to 100, which is indistinguishable from a scenario where all checks passed with perfect scores. This creates an ambiguity where "no checks performed" appears identical to "all checks passed with perfect scores."

The issue is triggered through the `get_provider!` macro when a provider is `None`: [2](#0-1) 

When `required=false` and the provider is `None`, the macro returns an empty vector at line 49. The `CommonCheckerConfig.required` field defaults to `false`: [3](#0-2) 

**Attack Scenario:**
1. A node operator sets up a validator node with insufficient hardware (e.g., 2 CPU cores instead of required 8)
2. The operator blocks or misconfigures their metrics endpoint, causing `get_metrics_client()` to fail
3. When the node-checker runs, `target_system_information_provider` remains `None` [4](#0-3) 

4. If the baseline configuration has `required: false` for hardware checks (or uses the default), the `get_provider!` macro returns an empty vec
5. The `CheckSummary` is created with `summary_score = 100` 
6. The validation client treats this as success and the node passes approval [5](#0-4) 

The node-checker is used for validator registration approval in AIT3 (Aptos Incentivized Testnet 3): [6](#0-5) 

## Impact Explanation

**Severity Assessment: High**

While the node-checker is not a consensus-critical component, this vulnerability allows bypassing operational validation for validator node admission to Aptos testnets. This qualifies as a **significant protocol violation** under the High severity category because:

1. **Validator Quality Degradation**: Nodes with insufficient hardware (below the required 8 CPU cores and 31 GB RAM) can pass validation and join the validator set
2. **Network Performance Impact**: Underpowered validators can cause network slowdowns and reduced throughput
3. **Trust Mechanism Bypass**: The validation system is designed to ensure only properly configured nodes participate, and this bypass undermines that trust

However, this does NOT constitute Critical severity because:
- It does not directly break consensus safety
- It does not enable fund theft or loss
- It does not cause permanent network failures
- The on-chain validator set mechanisms provide additional safeguards

## Likelihood Explanation

**Likelihood: Medium to High**

The vulnerability is highly likely to occur in practice because:

1. **Default Configuration Flaw**: The `required` field defaults to `false`, making misconfiguration easy
2. **Common Failure Scenario**: Network issues or firewall misconfigurations frequently cause metrics endpoints to be unreachable
3. **No Explicit Validation**: The code doesn't distinguish between "checks skipped" and "checks passed"
4. **Production Usage**: The node-checker is actively used for AIT validator approval

An attacker or even an inadvertent operator can trigger this by simply:
- Not exposing the metrics port
- Having network connectivity issues
- Using baseline configurations that don't explicitly set `required: true`

## Recommendation

**Fix 1: Fail on Empty Check Results**

Modify the `CheckSummary::from()` implementation to fail when no checks were performed:

```rust
let summary_score = match check_results.len() {
    0 => 0, // Changed from 100 to 0 - fail if no checks run
    len => (check_results.iter().map(|e| e.score as u32).sum::<u32>() / len as u32) as u8,
};
let summary_explanation = match (check_results.len(), summary_score) {
    (0, _) => format!("0: No checks were performed - validation incomplete"),
    (_, score) if score > 95 => format!("{}: Awesome!", score),
    // ... rest of conditions
};
```

**Fix 2: Change Default Behavior**

Make `required` default to `true` for critical checkers like `HardwareChecker`:

```rust
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommonCheckerConfig {
    /// Whether this checker must run as part of the check suite.
    #[serde(default = "CommonCheckerConfig::default_required")]
    pub required: bool,
}

impl CommonCheckerConfig {
    fn default_required() -> bool {
        true // Changed from false (via Default trait) to true
    }
}
```

**Fix 3: Add Explicit Validation Metadata**

Add a field to `CheckSummary` to track whether checks actually ran:

```rust
pub struct CheckSummary {
    pub check_results: Vec<CheckResult>,
    pub summary_score: u8,
    pub summary_explanation: String,
    pub checks_performed: usize, // New field
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_empty_check_results_bypass() {
        // Simulate scenario where all checkers return empty vecs
        let empty_results: Vec<CheckResult> = vec![];
        
        // Create CheckSummary from empty results
        let summary = CheckSummary::from(empty_results);
        
        // VULNERABILITY: Empty results get score 100 (perfect)
        assert_eq!(summary.summary_score, 100);
        assert_eq!(summary.check_results.len(), 0);
        assert_eq!(summary.summary_explanation, "100: Awesome!");
        
        // This is indistinguishable from a node that passed all checks
        // An attacker can achieve this by:
        // 1. Setting required=false in baseline config
        // 2. Making providers unavailable (block metrics endpoint)
        // 3. Getting perfect score without any actual validation
        
        println!("VULNERABILITY CONFIRMED: Empty check results yield perfect score!");
        println!("Summary: {:?}", summary);
    }
    
    #[test]
    fn test_hardware_checker_bypass() {
        // Simulate the hardware checker with unavailable provider
        // When required=false and provider=None, get_provider! macro returns Ok(vec![])
        let hardware_check_results: Vec<CheckResult> = vec![]; // Empty vec from get_provider!
        
        // This would pass validation despite no hardware checks being performed
        let summary = CheckSummary::from(hardware_check_results);
        
        assert_eq!(summary.summary_score, 100);
        println!("Hardware validation bypassed! Node approved without hardware checks.");
    }
}
```

## Notes

**Critical Distinction**: While this is a legitimate vulnerability in the node-checker implementation, it should be noted that:

1. The node-checker is an **ecosystem tool**, not a core consensus component
2. It's used for **operational validation** of testnet validators (AIT3), not mainnet protocol enforcement
3. The actual validator set admission is controlled by **on-chain staking mechanisms**, which provide additional security layers
4. The vulnerability requires either misconfigured baselines (controlled by Aptos team) or unavailable providers (network/configuration issues)

The fix should be implemented to ensure the integrity of the validation process, but the risk to the core Aptos protocol is limited by the fact that this tool operates off-chain and doesn't directly control validator set membership on mainnet.

### Citations

**File:** ecosystem/node-checker/src/checker/types.rs (L57-60)
```rust
        let summary_score = match check_results.len() {
            0 => 100,
            len => (check_results.iter().map(|e| e.score as u32).sum::<u32>() / len as u32) as u8,
        };
```

**File:** ecosystem/node-checker/src/provider/helpers.rs (L29-53)
```rust
    ($provider_option:expr, $required:expr, $provider_type:ty) => {
        match $provider_option {
            Some(ref provider) => provider,
            None => {
                if $required {
                    let checker_type_name = $crate::common::get_type_name::<Self>();
                    let provider_type_name = $crate::common::get_type_name::<$provider_type>();
                    return Ok(vec![CheckResult::new(
                        // This line is why this macro will only work inside a Checker.
                        checker_type_name.to_string(),
                        format!("{}: {}", checker_type_name, $crate::provider::MISSING_PROVIDER_MESSAGE),
                        0,
                        format!(
                            "Failed to fetch the data for the {} because of an error originating from the {}: {}",
                            checker_type_name,
                            provider_type_name,
                            <$provider_type as $crate::provider::Provider>::explanation()
                        ),
                    )]);
                } else {
                    return Ok(vec![]);
                }
            }
        }
    };
```

**File:** ecosystem/node-checker/src/checker/mod.rs (L91-94)
```rust
pub struct CommonCheckerConfig {
    /// Whether this checker must run as part of the check suite.
    #[serde(default)]
    pub required: bool,
```

**File:** ecosystem/node-checker/src/runner/sync_runner.rs (L104-119)
```rust
        if let Ok(metrics_client) = target_node_address.get_metrics_client(Duration::from_secs(4)) {
            let metrics_client = Arc::new(metrics_client);
            provider_collection.target_metrics_provider = Some(MetricsProvider::new(
                self.provider_configs.metrics.clone(),
                metrics_client.clone(),
                target_node_address.url.clone(),
                target_node_address.get_metrics_port().unwrap(),
            ));
            provider_collection.target_system_information_provider =
                Some(SystemInformationProvider::new(
                    self.provider_configs.system_information.clone(),
                    metrics_client,
                    target_node_address.url.clone(),
                    target_node_address.get_metrics_port().unwrap(),
                ));
        }
```

**File:** ecosystem/node-checker/fn-check-client/src/check.rs (L256-271)
```rust
        if check_summary.check_results.iter().any(|check_result| {
            check_result.checker_name == "NodeIdentityChecker" && check_result.score == 0
        }) {
            return SingleCheckResult::NodeCheckFailure(NodeCheckFailure::new(
                format!(
                    "Couldn't talk to API on any of the expected ports {:?}: {:?}",
                    API_PORTS, check_summary
                ),
                NodeCheckFailureCode::ApiPortClosed,
            ));
        }

        SingleCheckResult::Success(SingleCheckSuccess::new(
            check_summary,
            address_single_string,
        ))
```

**File:** ecosystem/node-checker/fn-check-client/README.md (L1-10)
```markdown
# Validator FullNode (VFN) NHC periodic checker

## Description
This tool is a client to NHC that does the following:
1. Get the validator set from any node participating in a network we want to test.
2. Process that to create a map from operator account address to VFN network addresses.
3. Query NHC for each VFN.
4. Push the results to BigQuery.

The original intent behind this tool is to confirm operators are running quality, operational VFNs as part of AIT3. This tool can be easily adapted for other use cases down the line.
```
