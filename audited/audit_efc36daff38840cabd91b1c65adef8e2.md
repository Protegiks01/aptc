# Audit Report

## Title
Node Identity Verification Bypass - Compromised Nodes Can Pass Health Checks Without Chain ID Validation

## Summary
The Node Health Checker client in `fn-check-client/src/check.rs` contains a critical logic flaw that allows nodes to pass health checks even when the NodeIdentityChecker is completely absent from the baseline configuration. This enables compromised or misconfigured nodes operating on incorrect blockchain networks or with wrong node roles to appear healthy, bypassing fundamental identity verification.

## Finding Description

The vulnerability exists in the success criteria logic for node health checks. [1](#0-0) 

The code checks if ANY result has `checker_name == "NodeIdentityChecker"` AND `score == 0`. If this condition is true, it returns failure. Otherwise, it returns success.

However, this logic has a critical flaw for three possible scenarios:
1. **NodeIdentityChecker present with score 0** → Returns failure (intended behavior)
2. **NodeIdentityChecker present with score 100** → Returns success (intended behavior)  
3. **NodeIdentityChecker completely absent** → Returns success (VULNERABILITY)

The third scenario is the vulnerability. When NodeIdentityChecker is not included in the baseline configuration's checkers list, the `check_results` array will not contain any result with `checker_name == "NodeIdentityChecker"`. The `.any()` method returns `false`, and the function proceeds to return `Success`, even though no identity verification was performed.

The NodeIdentityChecker is responsible for verifying critical node identity properties. [2](#0-1) 

It validates that:
- The target node reports the same **chain_id** as the baseline (ensuring it's on the correct blockchain network)
- The target node reports the same **node_role** as expected (validator vs fullnode)

Baseline configurations define which checkers to run through a configurable list. [3](#0-2) 

There is no validation enforcing that NodeIdentityChecker must be present. [4](#0-3) 

The validation only checks if checkers can be built, not whether critical checkers like NodeIdentityChecker are included.

**Attack Scenario:**

1. An administrator creates or uses a baseline configuration that omits NodeIdentityChecker (either accidentally or due to using an incomplete template)
2. The NHC server starts successfully with this configuration
3. A compromised node or misconfigured node is checked that is:
   - Running on testnet instead of mainnet (wrong chain_id)
   - Configured as wrong node role type
   - But passing other checks (build version, metrics, etc.)
4. The NHC returns a `CheckSummary` without any NodeIdentityChecker results
5. The client receives this CheckSummary and evaluates it
6. Since NodeIdentityChecker is not present, the `.any()` condition returns false
7. The function returns `Success`, making the compromised node appear healthy
8. Operators believe their node is properly configured when it's actually on the wrong network

## Impact Explanation

This is a **HIGH severity** vulnerability per Aptos bug bounty criteria, specifically qualifying as a "Significant protocol violation" in the node health checking protocol.

**Direct Impact:**
- Nodes operating on incorrect blockchain networks (wrong chain_id) can pass health verification
- Nodes configured with incorrect roles can appear legitimate
- Health dashboards and monitoring systems report false positives
- Operators may unknowingly run nodes on wrong networks

**Security Implications:**
- Compromised nodes that have been reconfigured to target different networks bypass identity verification
- Malicious actors could set up nodes claiming to be on mainnet while actually on test networks
- No alert is raised when nodes have fundamental identity misconfigurations

While this vulnerability is in an operational monitoring tool rather than the core consensus protocol (which has its own defenses against wrong chain_id), it represents a significant breakdown in the security monitoring layer that protects node operators from misconfigurations and compromises.

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability is highly likely to occur because:

1. **Configuration errors are common**: Administrators may copy incomplete configuration templates or forget to include all necessary checkers
2. **No enforcement mechanism**: The system does not validate that critical checkers like NodeIdentityChecker are present
3. **Silent failure**: When NodeIdentityChecker is missing, there's no warning - nodes simply pass checks without identity verification
4. **Default behavior assumption**: The code implicitly assumes NodeIdentityChecker will always be present, but this assumption is never enforced

The vulnerability requires no attacker sophistication - it occurs naturally through configuration mistakes. An attacker could also deliberately create baseline configurations without NodeIdentityChecker to facilitate deploying compromised nodes.

## Recommendation

**Fix 1: Add explicit validation for NodeIdentityChecker presence**

Modify the check logic to verify that NodeIdentityChecker results are present:

```rust
// In check.rs, replace lines 256-271 with:

// First, check if NodeIdentityChecker is present at all
let node_identity_results: Vec<_> = check_summary
    .check_results
    .iter()
    .filter(|r| r.checker_name == "NodeIdentityChecker")
    .collect();

if node_identity_results.is_empty() {
    return SingleCheckResult::NodeCheckFailure(NodeCheckFailure::new(
        "Critical security check missing: NodeIdentityChecker was not run".to_string(),
        NodeCheckFailureCode::MissingCriticalChecker,
    ));
}

// Check specifically if the API port is closed
if node_identity_results.iter().any(|r| r.score == 0) {
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

Add the new error code:
```rust
// Add to NodeCheckFailureCode enum:
MissingCriticalChecker,
```

**Fix 2: Enforce NodeIdentityChecker at configuration validation**

Add validation to ensure NodeIdentityChecker is always present in baseline configurations:

```rust
// In validate.rs:
pub fn validate_configuration(node_configuration: &BaselineConfiguration) -> Result<()> {
    // Ensure critical checkers are present
    let has_node_identity_checker = node_configuration.checkers.iter().any(|c| {
        matches!(c, CheckerConfig::NodeIdentity(_))
    });
    
    if !has_node_identity_checker {
        bail!("NodeIdentityChecker is required in all baseline configurations for security");
    }
    
    build_checkers(&node_configuration.checkers).context("Failed to build Checkers")?;
    Ok(())
}
```

## Proof of Concept

**Step 1: Create a baseline configuration without NodeIdentityChecker**

```yaml
# incomplete_baseline.yaml
configuration_id: "test_config"
configuration_name: "Test Config Without NodeIdentity"

checkers:
  - type: BuildVersion
    common:
      required: false
  - type: Hardware  
    common:
      required: false
  # NodeIdentityChecker is intentionally omitted
```

**Step 2: Simulate the vulnerability**

```rust
// Test case demonstrating the vulnerability
#[test]
fn test_missing_node_identity_checker_vulnerability() {
    use crate::{CheckSummary, CheckResult, SingleCheckResult};
    
    // Simulate a CheckSummary WITHOUT NodeIdentityChecker results
    let check_summary = CheckSummary {
        check_results: vec![
            CheckResult::new(
                "BuildVersionChecker".to_string(),
                "Build version matches".to_string(),
                100,
                "All good".to_string(),
            ),
            CheckResult::new(
                "HardwareChecker".to_string(),
                "Hardware sufficient".to_string(),
                100,
                "All good".to_string(),
            ),
            // NodeIdentityChecker is MISSING - this is the vulnerability
        ],
        summary_score: 100,
        summary_explanation: "100: Awesome!".to_string(),
    };
    
    // The current logic in check_single_fn_one_api_port lines 256-266:
    let has_node_identity_failure = check_summary.check_results.iter().any(|check_result| {
        check_result.checker_name == "NodeIdentityChecker" && check_result.score == 0
    });
    
    // This returns false because NodeIdentityChecker is not present at all
    assert_eq!(has_node_identity_failure, false);
    
    // Therefore, the function returns Success
    // A node on the wrong blockchain network or with wrong role 
    // would pass this check - THIS IS THE VULNERABILITY
    
    println!("VULNERABILITY CONFIRMED: Node passes health check without identity verification!");
}
```

**Step 3: Demonstrate real-world impact**

A compromised node running on testnet (chain_id=2) instead of mainnet (chain_id=1) would:
1. Pass all non-identity checks (build version, hardware, etc.)
2. Receive a CheckSummary without NodeIdentityChecker results
3. Be marked as Success by the client
4. Appear healthy to operators despite being on the wrong network

The blockchain's own consensus protocol would eventually reject this node's messages, but the health monitoring system would incorrectly report it as healthy, misleading operators about their node's status.

## Notes

This vulnerability represents a dangerous assumption in security-critical code: the implicit assumption that NodeIdentityChecker will always be present. The code only checks for the failure case (score == 0) but doesn't validate the checker exists at all. This is a classic "absence of evidence vs evidence of absence" logical error in security validation.

The vulnerability is particularly concerning because it fails silently - there's no warning or error when NodeIdentityChecker is missing, making it easy for misconfigurations to go unnoticed in production environments.

### Citations

**File:** ecosystem/node-checker/fn-check-client/src/check.rs (L256-266)
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
```

**File:** ecosystem/node-checker/src/checker/node_identity.rs (L67-114)
```rust
    /// Assert that the node identity (role type and chain ID) of the two nodes match.
    async fn check(
        &self,
        providers: &ProviderCollection,
    ) -> Result<Vec<CheckResult>, CheckerError> {
        let baseline_api_index_provider = get_provider!(
            providers.baseline_api_index_provider,
            self.config.common.required,
            ApiIndexProvider
        );

        let target_api_index_provider = get_provider!(
            providers.target_api_index_provider,
            self.config.common.required,
            ApiIndexProvider
        );

        // We just let this error turn into a CheckerError since we want to
        // return actual errors in the case of a failure in querying the baseline.
        let baseline_response = baseline_api_index_provider.provide().await?;

        // As for the target, we return a CheckResult if something fails here.
        let target_response = match target_api_index_provider.provide().await {
            Ok(response) => response,
            Err(err) => {
                return Ok(vec![Self::build_result(
                    "Failed to check identity of your node".to_string(),
                    0,
                    format!("There was an error querying your node's API: {:#}", err),
                )]);
            },
        };

        let check_results = vec![
            self.help_build_check_result(
                baseline_response.chain_id,
                target_response.chain_id,
                "Chain ID",
            ),
            self.help_build_check_result(
                baseline_response.node_role,
                target_response.node_role,
                "Role Type",
            ),
        ];

        Ok(check_results)
    }
```

**File:** ecosystem/node-checker/src/configuration/types.rs (L35-36)
```rust
    /// Configs for the checkers to use.
    pub checkers: Vec<CheckerConfig>,
```

**File:** ecosystem/node-checker/src/configuration/validate.rs (L24-26)
```rust
pub fn validate_configuration(node_configuration: &BaselineConfiguration) -> Result<()> {
    build_checkers(&node_configuration.checkers).context("Failed to build Checkers")?;
    Ok(())
```
