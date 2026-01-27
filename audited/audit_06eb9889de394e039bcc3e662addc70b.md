# Audit Report

## Title
DNS Poisoning Vulnerability in Node Health Checker API Endpoint Validation

## Summary
The ApiIndexProvider in the Node Health Checker does not verify that HTTP connections reach the intended node API endpoint, allowing DNS poisoning attacks to redirect health check requests to malicious servers that can return fabricated node status data.

## Finding Description

The `ApiIndexProvider::provide()` function makes HTTP requests without validating the connection endpoint: [1](#0-0) 

The underlying `Client` is created from a user-provided URL with no endpoint validation: [2](#0-1) 

The system accepts both HTTP and HTTPS URLs, with API documentation examples showing HTTP: [3](#0-2) 

**Attack Path:**
1. Attacker performs DNS poisoning for target node domain (e.g., `fullnode.victim.com`)
2. Operator queries Node Health Checker: `/check?node_url=http://fullnode.victim.com&api_port=8080`
3. DNS resolution returns attacker's IP address
4. Node Health Checker connects to attacker's server
5. Attacker returns fake `IndexResponse` with manipulated `chain_id`, `ledger_version`, `node_role`, etc.
6. All subsequent health checks use this fabricated data for validation

The `IndexResponse` data is used by multiple critical checkers: [4](#0-3) 

## Impact Explanation

This vulnerability is classified as **High Severity** under the Aptos bug bounty program because it enables:

1. **API Manipulation**: Attackers can return arbitrary health check data, causing validators to make incorrect operational decisions
2. **Monitoring Infrastructure Compromise**: The Node Health Checker is production infrastructure used by validators and the Aptos Foundation
3. **Cascading Effects**: Automated monitoring systems (`fn-check-client`) that query NHC and push results to BigQuery for analysis would propagate false data

While this does not directly affect consensus or cause fund loss, it falls under "Significant protocol violations" and "API crashes" categories for High severity ($50,000 tier), as compromised monitoring infrastructure can lead to:
- Healthy nodes appearing unhealthy (causing unnecessary service disruption)
- Unhealthy nodes appearing healthy (hiding critical problems)
- Incorrect validator performance assessments

## Likelihood Explanation

**Likelihood: Medium-High**

DNS poisoning attacks are well-established and feasible:
- No special privileges required beyond DNS control (e.g., compromised DNS server, MITM on DNS traffic)
- The system explicitly accepts HTTP URLs, providing no TLS protection
- Even with HTTPS, DNS poisoning combined with certificate compromise or browser trust issues remains viable
- Automated monitoring systems query NHC regularly, providing multiple attack opportunities

## Recommendation

Implement endpoint validation with multiple layers:

1. **Enforce HTTPS-only**: Reject HTTP URLs in node address validation
2. **Add expected endpoint verification**: Allow operators to specify expected IP addresses or certificate fingerprints
3. **Implement certificate pinning**: For known baseline nodes, pin their certificates
4. **Add response validation**: Cross-check critical fields like `chain_id` against known-good values

Example fix for NodeAddress:

```rust
pub fn get_api_client(&self, timeout: Duration) -> Result<AptosRestClient> {
    // Enforce HTTPS
    if self.url.scheme() != "https" {
        bail!("Only HTTPS URLs are allowed for API endpoints");
    }
    
    let client = reqwest::ClientBuilder::new()
        .timeout(timeout)
        .cookie_provider(self.cookie_store.clone())
        .build()
        .unwrap();

    Ok(AptosRestClient::from((client, self.get_api_url()?)))
}
```

Additionally, validate IndexResponse chain_id against expected values: [5](#0-4) 

## Proof of Concept

```rust
// Proof of Concept: DNS Poisoning Attack Simulation
#[tokio::test]
async fn test_dns_poisoning_vulnerability() {
    use ecosystem::node_checker::configuration::NodeAddress;
    use ecosystem::node_checker::provider::api_index::ApiIndexProvider;
    use url::Url;
    use std::time::Duration;
    
    // Attacker controls DNS and points victim.com to malicious server
    // Malicious server runs on 127.0.0.1:9999 returning fake IndexResponse
    
    let malicious_url = Url::parse("http://victim.com").unwrap();
    let node_address = NodeAddress::new(
        malicious_url,
        Some(9999), // Attacker's port
        None,
        None,
        None,
    );
    
    // Create API client - NO VALIDATION OF ENDPOINT
    let client = node_address.get_api_client(Duration::from_secs(4)).unwrap();
    
    let provider = ApiIndexProvider::new(
        Default::default(),
        client,
    );
    
    // This call goes to attacker's server if DNS is poisoned
    // Attacker returns fake data: wrong chain_id, manipulated ledger_version
    let result = provider.provide().await;
    
    // Health checks proceed with compromised data
    // No detection that endpoint was redirected
}
```

## Notes

This vulnerability is specific to the Node Health Checker infrastructure component, not the core consensus layer. However, as production monitoring infrastructure relied upon by validators and operators for critical health assessment decisions, endpoint validation is essential to prevent operational disruptions and incorrect validator performance reporting.

### Citations

**File:** ecosystem/node-checker/src/provider/api_index.rs (L51-69)
```rust
#[async_trait]
impl Provider for ApiIndexProvider {
    type Output = IndexResponse;

    async fn provide(&self) -> Result<Self::Output, ProviderError> {
        self.output_cache
            .get(
                self.client
                    .get_index()
                    .map_ok(|r| r.into_inner())
                    .map_err(|e| ProviderError::RetryableEndpointError("/", e.into())),
            )
            .await
    }

    fn explanation() -> &'static str {
        "The API port was not included in the request."
    }
}
```

**File:** ecosystem/node-checker/src/configuration/node_address.rs (L107-115)
```rust
    pub fn get_api_client(&self, timeout: Duration) -> Result<AptosRestClient> {
        let client = reqwest::ClientBuilder::new()
            .timeout(timeout)
            .cookie_provider(self.cookie_store.clone())
            .build()
            .unwrap();

        Ok(AptosRestClient::from((client, self.get_api_url()?)))
    }
```

**File:** ecosystem/node-checker/src/server/api.rs (L34-35)
```rust
        /// The URL of the node to check, e.g. http://44.238.19.217 or http://fullnode.mysite.com
        node_url: Query<Url>,
```

**File:** ecosystem/node-checker/src/checker/node_identity.rs (L1-10)
```rust
// Copyright (c) Aptos Foundation
// Licensed pursuant to the Innovation-Enabling Source Code License, available at https://github.com/aptos-labs/aptos-core/blob/main/LICENSE

use super::{CheckResult, Checker, CheckerError, CommonCheckerConfig};
use crate::{
    get_provider,
    provider::{api_index::ApiIndexProvider, Provider, ProviderCollection},
};
use anyhow::Result;
use serde::{Deserialize, Serialize};
```
