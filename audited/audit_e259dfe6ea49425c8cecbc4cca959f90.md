# Audit Report

## Title
Configuration Version Skew Allows Silent Security Check Bypass in Node Health Checker

## Summary
The `BaselineConfiguration` deserialization in the Node Health Checker allows security checks to be silently skipped when the `required` field is missing from checker configurations due to version skew. When `required` defaults to `false` and providers are unavailable, checkers return empty results, causing the system to assign a perfect score (100) despite no validation occurring.

## Finding Description

The vulnerability exists in the configuration deserialization and check result aggregation logic:

**1. Default Value Issue:** [1](#0-0) 

The `CommonCheckerConfig.required` field has `#[serde(default)]`, causing it to default to `false` when missing from configuration files.

**2. Silent Skip Mechanism:** [2](#0-1) 

When `required` is `false` and a provider is unavailable, the `get_provider!` macro returns `Ok(vec![])` (line 49), silently skipping the check without any error indication.

**3. Score Calculation Flaw:** [3](#0-2) 

The critical flaw is at line 58: when `check_results.len() == 0`, the `summary_score` is set to `100` (perfect score), even though no security checks actually executed.

**Attack Scenario:**

1. Old configuration files are deployed that don't explicitly set `required: true` for security-critical checkers (e.g., ConsensusProposalsChecker, HandshakeChecker)
2. During system upgrades or version skew, these fields default to `false`
3. If required providers fail to initialize (network issues, port blocking, API unavailable), all checkers silently return empty results
4. The final `CheckSummary` has `check_results = []` and `summary_score = 100`
5. Nodes that should fail validation pass with perfect scores [4](#0-3) [5](#0-4) 

## Impact Explanation

**Severity Assessment: Does NOT meet Medium severity criteria**

While this is a legitimate configuration management issue, upon careful evaluation against the Aptos Bug Bounty criteria, this vulnerability **does not qualify as Medium severity** because:

1. **Node Health Checker is not part of core blockchain infrastructure** - It's an external operational monitoring tool used for validator qualification, not part of consensus, execution, storage, governance, or staking systems

2. **No direct security impact on blockchain operation**:
   - Does NOT affect consensus safety or liveness
   - Does NOT enable funds theft or manipulation
   - Does NOT cause state inconsistencies in the blockchain
   - Does NOT affect validator set selection (on-chain validation in `stake.move` is separate)

3. **Operational monitoring bypass only** - This affects operational validation of nodes, not the blockchain protocol itself [6](#0-5) 

The tool is used for "confirming operators are running quality, operational VFNs" but is not a security gate for the blockchain itself.

## Likelihood Explanation

**Likelihood: Low to Medium**

The vulnerability requires:
- Deployment of configuration files missing explicit `required: true` settings
- Version skew during system upgrades
- Provider initialization failures (network issues, misconfiguration)

However, the startup validation process does test configurations against baseline nodes, which would catch some cases: [7](#0-6) 

## Recommendation

**1. Make critical checkers required by default:**

```rust
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommonCheckerConfig {
    /// Whether this checker must run as part of the check suite.
    /// Defaults to true for security
    #[serde(default = "CommonCheckerConfig::default_required")]
    pub required: bool,
}

impl CommonCheckerConfig {
    fn default_required() -> bool {
        true  // Fail-safe default
    }
}
```

**2. Add explicit validation that critical checks executed:**

```rust
impl From<Vec<CheckResult>> for CheckSummary {
    fn from(check_results: Vec<CheckResult>) -> Self {
        let summary_score = match check_results.len() {
            0 => {
                // Empty results should be treated as failure, not success
                warn!("No check results returned - possible configuration error");
                0
            },
            len => (check_results.iter().map(|e| e.score as u32).sum::<u32>() / len as u32) as u8,
        };
        // ... rest of implementation
    }
}
```

**3. Add configuration validation at startup** to ensure all critical checkers have `required: true`.

## Proof of Concept

```rust
// Reproduction test
#[tokio::test]
async fn test_version_skew_silent_bypass() {
    // Create config with missing 'required' field
    let config_yaml = r#"
configuration_id: "test_config"
configuration_name: "Test Config"
checkers:
  - type: ConsensusProposals
    # Note: 'required' field is missing, defaults to false
"#;
    
    let cfg: BaselineConfiguration = serde_yaml::from_str(config_yaml).unwrap();
    
    // Build runner with unavailable providers
    let provider_collection = ProviderCollection::new(); // Empty providers
    let checkers = build_checkers(&cfg.checkers).unwrap();
    let runner = SyncRunner::new(
        cfg.runner_config,
        provider_collection,
        cfg.provider_configs,
        checkers,
    );
    
    // Run against a node address (providers will be unavailable)
    let target = NodeAddress::new(
        Url::parse("http://invalid.local").unwrap(),
        None, None, None, None
    );
    
    let result = runner.run(&target).await.unwrap();
    
    // BUG: Empty results get perfect score!
    assert_eq!(result.check_results.len(), 0);
    assert_eq!(result.summary_score, 100); // VULNERABLE: Perfect score with no checks
}
```

## Notes

**Important Context:**

After thorough analysis against the strict validation checklist, **this issue does NOT meet the criteria for a valid security vulnerability** in the Aptos Bug Bounty program because:

1. Node Health Checker is an **external operational tool**, not part of the core blockchain protocol
2. It does NOT affect any of the 10 critical invariants (consensus, execution, storage, governance, staking)
3. The impact is limited to operational monitoring and does not demonstrate security harm to funds, consensus, or blockchain availability

While this is a legitimate **configuration management and operational monitoring concern**, it should be classified as a **best practices improvement** rather than a security vulnerability requiring bounty payout.

The appropriate classification would be **Low Severity** (non-critical implementation bug) at most, but the bug bounty program focus is on core blockchain components, not external tooling.

### Citations

**File:** ecosystem/node-checker/src/checker/mod.rs (L89-95)
```rust
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommonCheckerConfig {
    /// Whether this checker must run as part of the check suite.
    #[serde(default)]
    pub required: bool,
}
```

**File:** ecosystem/node-checker/src/provider/helpers.rs (L28-54)
```rust
macro_rules! get_provider {
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
}
```

**File:** ecosystem/node-checker/src/checker/types.rs (L54-73)
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
        CheckSummary {
            check_results,
            summary_score,
            summary_explanation,
        }
    }
}
```

**File:** ecosystem/node-checker/src/checker/handshake.rs (L48-52)
```rust
        let target_noise_provider = get_provider!(
            providers.target_noise_provider,
            self.config.common.required,
            NoiseProvider
        );
```

**File:** ecosystem/node-checker/src/checker/consensus_proposals.rs (L89-93)
```rust
        let target_metrics_provider = get_provider!(
            providers.target_metrics_provider,
            self.config.common.required,
            MetricsProvider
        );
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

**File:** ecosystem/node-checker/src/server/build.rs (L172-199)
```rust
    if let Some(node_address) = &configuration.node_address {
        let message = format!(
            "Failed to run the Checker suite against the baseline node itself \
                for {}. This implies that a Checker has been enabled in the baseline \
                config but the necessary baseline information was not provided. For \
                example, this error might happen if the NodeIdentityChecker was enabled \
                but the API port for the baseline was not provided, since that checker \
                needs to be able to query the API of the baseline node. ",
            configuration.configuration_id
        );
        let results = runner
            .run(node_address)
            .await
            .with_context(|| message.clone())?;
        let mut missing_provider_results = Vec::new();
        for result in results.check_results.into_iter() {
            if result.score < 100 && result.headline.ends_with(MISSING_PROVIDER_MESSAGE) {
                missing_provider_results.push(result);
            }
        }
        if !missing_provider_results.is_empty() {
            bail!(
                "{} The following check results should explain the problem: {:#?}",
                message,
                missing_provider_results
            );
        }
    }
```
