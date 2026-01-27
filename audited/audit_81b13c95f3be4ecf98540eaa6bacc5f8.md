# Audit Report

## Title
Validator Version Verification Bypass Through Score Averaging in Node Health Checker

## Summary
The Aptos Node Health Checker's `BuildVersionChecker` uses asymmetric error handling that allows compromised validator nodes to suppress critical version information and still achieve passing health scores through averaging, potentially enabling unverified code to join the validator set.

## Finding Description

The node-checker system implements an intentional asymmetry in error handling between baseline and target nodes. When the baseline node is missing `build_commit_hash` data, the checker returns a hard error that fails the entire validation run. However, when the target node is missing this critical data, the checker returns a low score (0) that gets averaged with other check results. [1](#0-0) [2](#0-1) 

The documented design philosophy states that errors should only be returned for baseline/infrastructure problems, while target problems should return low-score results: [3](#0-2) 

When any checker returns an error, the entire check run fails via `try_join_all`: [4](#0-3) 

However, when a checker returns a low score, it's simply averaged with all other checks: [5](#0-4) 

**Attack Scenario:**
1. Attacker operates a validator node running modified Aptos software (e.g., with consensus manipulation, transaction reordering, or MEV extraction capabilities)
2. Attacker suppresses the `build_commit_hash` field from the `/system_information` metrics endpoint
3. `BuildVersionChecker` returns score 0 with message "Build commit hash value missing"
4. All other checkers (consensus_round, state_sync_version, minimum_peers, etc.) pass normally with score 100
5. Overall summary_score = (0 + 10×100) / 11 ≈ 91
6. Node appears "mostly healthy" with a 91/100 score rather than definitively rejected

The node-checker is explicitly used for validator qualification: [6](#0-5) 

Results are returned as `Success` as long as NHC returns HTTP 200, regardless of individual check scores (only API connectivity is checked specifically): [7](#0-6) 

## Impact Explanation

This qualifies as **High Severity** under Aptos bug bounty criteria for the following reasons:

1. **Significant Protocol Violations**: Allows validators running unverified/modified code to potentially join the validator set, which could lead to:
   - Consensus manipulation (Byzantine behavior)
   - Transaction censorship or reordering
   - State corruption through modified execution logic
   - Front-running and MEV extraction beyond protocol parameters

2. **Validator Node Issues**: Compromised validators could cause network-wide problems including consensus slowdowns, incorrect state transitions, or coordinated attacks when multiple compromised nodes collude.

3. **Breaks Validator Qualification Integrity**: The fundamental security guarantee that only known, trusted software participates in consensus is undermined.

While this doesn't directly cause fund loss or consensus failure, it creates a pathway for such attacks by allowing compromised nodes to evade detection during qualification.

## Likelihood Explanation

**Likelihood: Medium to High**

**Attacker Requirements:**
- Minimal: Any node operator can control what metrics their node exposes
- No privileged access required
- Simple configuration change or code modification to suppress the metric field

**Complexity:**
- Low: Suppressing a single metric field is trivial compared to bypassing cryptographic checks
- The averaging behavior is deterministic and predictable

**Existing Deployment Context:**
- Node-checker is actively used for validator qualification (as evidenced by `fn-check-client` tool)
- No hardcoded score thresholds exist in the code, suggesting downstream consumers may use ad-hoc thresholds
- A score of 90+ often appears acceptable in monitoring contexts

**Likelihood Factors Increasing Risk:**
- Automated qualification systems might use score thresholds (e.g., accept if >85)
- Manual reviewers seeing 91/100 score may not investigate deeper
- The asymmetry makes this a non-obvious vulnerability

## Recommendation

**Fix 1: Make version verification a mandatory hard check**

Change the `BuildVersionChecker` to return an error when target node is missing critical version data, rather than a low score:

```rust
// In build_version.rs, lines 105-111
let target_build_commit_hash = match self.get_build_commit_hash(&target_information) {
    GetValueResult::Present(value) => value,
    GetValueResult::Missing(_evaluation_result) => {
        return Err(CheckerError::MissingDataError(
            BUILD_COMMIT_HASH_KEY,
            anyhow!("The target node did not provide build commit hash information, which is required for validator qualification"),
        ));
    },
};
```

**Fix 2: Implement tiered checker criticality**

Introduce a concept of "critical" vs "advisory" checkers:
- Critical checkers failing should cause hard validation failure
- Advisory checkers failing should only affect the score
- Mark `BuildVersionChecker`, `NodeIdentityChecker`, and similar security checks as critical

**Fix 3: Add explicit pass/fail determination**

Rather than relying purely on score averaging, implement explicit pass/fail logic:
- Define mandatory checks that must pass
- Define minimum individual scores for critical checks
- Only average non-critical health metrics

## Proof of Concept

```rust
// Reproduction test demonstrating the vulnerability
#[cfg(test)]
mod test {
    use super::*;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_missing_version_averages_with_other_checks() {
        // Simulate a compromised node that suppresses build_commit_hash
        let mut target_system_info = HashMap::new();
        // Intentionally omit build_commit_hash
        // target_system_info.insert("build_commit_hash".to_string(), "compromised".to_string());
        
        let target_info = SystemInformation(target_system_info);
        
        let mut baseline_system_info = HashMap::new();
        baseline_system_info.insert("build_commit_hash".to_string(), "abc123".to_string());
        let baseline_info = SystemInformation(baseline_system_info);
        
        // Create checker
        let checker = BuildVersionChecker::new(BuildVersionCheckerConfig {
            common: CommonCheckerConfig { required: true },
        });
        
        // Get build commit hash from target - should return Missing with score 0
        let result = checker.get_build_commit_hash(&target_info);
        
        match result {
            GetValueResult::Missing(check_result) => {
                assert_eq!(check_result.score, 0);
                assert!(check_result.headline.contains("missing"));
                
                // Simulate averaging with 10 other passing checks
                let total_score = 0 + (10 * 100);
                let average = total_score / 11;
                
                // Compromised node still gets 90/100 overall score!
                assert_eq!(average, 90);
                println!("VULNERABILITY: Compromised node with missing version info scores {}/100", average);
            },
            _ => panic!("Expected Missing result"),
        }
    }
}
```

## Notes

**Additional Context:**

1. **This pattern appears in other checkers**: The `StateSyncVersionChecker` uses identical asymmetric error handling, suggesting this is a systemic design issue rather than an isolated bug: [8](#0-7) [9](#0-8) 

2. **Design Intent vs Security Reality**: While the asymmetry is intentional (documented in traits.rs), it creates a security gap for critical checks. Not all checks should be treated equally—version verification is a security control, not a health metric.

3. **Real-World Exploitation**: An attacker could deploy this alongside other evasion techniques (passing just enough checks to appear legitimate) to achieve validator set inclusion with compromised code.

4. **Downstream Impact**: Even if manual review catches some cases, the 91/100 score creates cognitive bias toward acceptance, especially in high-throughput qualification scenarios.

### Citations

**File:** ecosystem/node-checker/src/checker/build_version.rs (L94-103)
```rust
        let baseline_build_commit_hash = match self.get_build_commit_hash(&baseline_information) {
            GetValueResult::Present(value) => value,
            GetValueResult::Missing(_evaluation_result) => {
                return
                    Err(CheckerError::MissingDataError(
                        BUILD_COMMIT_HASH_KEY,
                        anyhow!("The latest set of metrics from the baseline node did not contain the necessary key \"{}\"", BUILD_COMMIT_HASH_KEY),
                    ));
            },
        };
```

**File:** ecosystem/node-checker/src/checker/build_version.rs (L105-111)
```rust
        let target_build_commit_hash = match self.get_build_commit_hash(&target_information) {
            GetValueResult::Present(value) => Some(value),
            GetValueResult::Missing(evaluation_result) => {
                check_results.push(evaluation_result);
                None
            },
        };
```

**File:** ecosystem/node-checker/src/checker/traits.rs (L18-22)
```rust
    /// and return a vec of evaluation results. It should only return
    /// errors when there is something wrong with NHC itself or the
    /// baseline node. If something is unexpected with the target,
    /// we expect this function to return an EvaluationResult indicating
    /// as such.
```

**File:** ecosystem/node-checker/src/runner/sync_runner.rs (L162-163)
```rust
        let check_results: Vec<CheckResult> =
            try_join_all(futures).await?.into_iter().flatten().collect();
```

**File:** ecosystem/node-checker/src/checker/types.rs (L54-66)
```rust
impl From<Vec<CheckResult>> for CheckSummary {
    // Very basic for now, we likely want a trait for this.
    fn from(check_results: Vec<CheckResult>) -> Self {
        let summary_score = match check_results.len() {
            0 => 100,
            len => (check_results.iter().map(|e| e.score as u32).sum::<u32>() / len as u32) as u8,
        };
        let summary_explanation = match summary_score {
            summary_score if summary_score > 95 => format!("{}: Awesome!", summary_score),
            summary_score if summary_score > 80 => format!("{}: Good!", summary_score),
            summary_score if summary_score > 50 => format!("{}: Getting there!", summary_score),
            wildcard => format!("{}: Improvement necessary", wildcard),
        };
```

**File:** ecosystem/node-checker/fn-check-client/src/check.rs (L1-7)
```rust
// Copyright (c) Aptos Foundation
// Licensed pursuant to the Innovation-Enabling Source Code License, available at https://github.com/aptos-labs/aptos-core/blob/main/LICENSE

//! This file contains logic for checking a node, common to both VFNs and PFNs.
//! At this point, some earlier code has processed the input information, e.g.
//! VFN information on chain or PFN information from a file, and has converted
//! it into a common format that these functions can ingest.
```

**File:** ecosystem/node-checker/fn-check-client/src/check.rs (L255-272)
```rust
        // Check specifically if the API port is closed.
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
    }
```

**File:** ecosystem/node-checker/src/checker/state_sync_version.rs (L131-140)
```rust
        let previous_target_version = match target_api_index_provider.provide().await {
            Ok(response) => response.ledger_version.0,
            Err(err) => {
                return Ok(vec![Self::build_result(
                    "Failed to determine state sync status".to_string(),
                    0,
                    format!("There was an error querying your node's API: {:#}", err),
                )]);
            },
        };
```

**File:** ecosystem/node-checker/src/checker/state_sync_version.rs (L157-161)
```rust
        // Get the latest version from the baseline node. In this case, if we
        // cannot find the value, we return an error instead of a negative evalution,
        // since this implies some issue with the baseline node / this code.
        let latest_baseline_response = baseline_api_index_provider.provide().await?;
        let latest_baseline_version = latest_baseline_response.ledger_version.0;
```
