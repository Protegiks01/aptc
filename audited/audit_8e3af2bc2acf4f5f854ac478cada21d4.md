# Audit Report

## Title
Unbounded Memory Consumption in Node-Checker OutputCache via Malicious IndexResponse

## Summary
The `OutputCache` implementation in the node-checker lacks size limits on cached data, allowing malicious external nodes to trigger memory exhaustion by returning `IndexResponse` objects with arbitrarily large `git_hash` fields.

## Finding Description

The node-checker's `ApiIndexProvider` uses an `OutputCache` to cache `IndexResponse` data from external nodes being monitored. [1](#0-0) 

The `OutputCache` implementation stores cached values in a simple `RwLock<Option<T>>` structure with no size constraints. [2](#0-1)  When new data is fetched, it replaces the previous cached value and stores it for the configured TTL duration. [3](#0-2) 

The `IndexResponse` struct contains a `git_hash: Option<String>` field that has no size validation. [4](#0-3)  When the REST client deserializes JSON responses from external nodes, it uses reqwest's default JSON deserialization which imposes no size limits. [5](#0-4) 

**Attack Propagation:**

1. A malicious node operator modifies their node's API endpoint to return an `IndexResponse` with an extremely large `git_hash` field (e.g., 1GB string)
2. The node-checker (used to evaluate testnet participants or monitor nodes) queries this malicious node
3. The REST client deserializes the response without size validation
4. The large `IndexResponse` object is stored in `OutputCache` and held in memory for the cache TTL (default 1 second, but configurable up to minutes)
5. If the fn-check-client checks multiple malicious nodes concurrently (up to 32 by default), each creates a separate provider instance with its own cache [6](#0-5) 
6. Memory consumption multiplies: 32 nodes × 1GB each = 32GB consumed

## Impact Explanation

This vulnerability enables a **Denial of Service (DoS) attack** against node-checker infrastructure used for testnet evaluation and node monitoring.

**Realistic Attack Scenario:** During incentivized testnets (like AIT3), testnet operators use fn-check-client to evaluate all registered validator nodes. Malicious participants could register nodes that return oversized responses, causing the evaluation infrastructure to crash with OOM errors, disrupting the testnet's ability to onboard and monitor participants.

**However**, this vulnerability has significant limitations:
- It only affects the **node-checker service**, not blockchain validators or consensus nodes
- The node-checker is a **monitoring tool**, not a consensus-critical component
- According to the bug bounty exclusions, "Network-level DoS attacks are out of scope"
- The impact is limited to monitoring infrastructure availability

Given these limitations, this issue does **not clearly fit** the defined severity categories (Critical/High/Medium) which focus on funds loss, consensus violations, or validator node impacts. While it's a real implementation flaw, it may fall outside the scope of vulnerabilities that affect blockchain security directly.

## Likelihood Explanation

**Likelihood: High** in testnet evaluation scenarios where:
- Multiple untrusted nodes are evaluated concurrently
- Attackers can register malicious nodes for evaluation
- The node-checker service processes requests from these nodes

**Likelihood: Low** in production monitoring scenarios where:
- Operators typically monitor their own nodes or known trusted nodes
- Configuration is controlled and vetted

## Recommendation

Implement size limits on cached responses:

1. **Add response size validation** before caching:
   - Add a max_cache_size_bytes configuration option to CommonProviderConfig
   - Validate response size before storing in OutputCache
   - Return an error if response exceeds the limit

2. **Implement field-level validation** for IndexResponse:
   - Add max length validation for the git_hash field (git hashes should be 40-64 characters)
   - Validate during deserialization using serde validators

3. **Add reqwest client size limits**:
   - Configure reqwest client with response size limits using client builder options

## Proof of Concept

```rust
// This PoC demonstrates the vulnerability by creating a mock malicious node
// that returns an oversized git_hash field

#[cfg(test)]
mod test {
    use super::*;
    use httpmock::prelude::*;
    use aptos_rest_client::Client;
    
    #[tokio::test]
    async fn test_unbounded_cache_memory() {
        // Start mock server representing malicious node
        let server = MockServer::start();
        
        // Create large git_hash (100MB)
        let large_git_hash = "A".repeat(100_000_000);
        
        // Mock response with oversized git_hash
        let mock = server.mock(|when, then| {
            when.method(GET).path("/");
            then.status(200)
                .header("content-type", "application/json")
                .json_body(json!({
                    "chain_id": 1,
                    "epoch": "0",
                    "ledger_version": "0",
                    "oldest_ledger_version": "0",
                    "ledger_timestamp": "0",
                    "node_role": "FullNode",
                    "oldest_block_height": "0",
                    "block_height": "0",
                    "git_hash": large_git_hash
                }));
        });
        
        // Create ApiIndexProvider with malicious node client
        let client = Client::new(server.base_url().parse().unwrap());
        let config = ApiIndexProviderConfig::default();
        let provider = ApiIndexProvider::new(config, client);
        
        // Fetch data - this will cache the 100MB response
        let response = provider.provide().await.unwrap();
        
        // The 100MB git_hash is now cached in memory
        assert!(response.git_hash.as_ref().unwrap().len() == 100_000_000);
        
        // Memory remains consumed until TTL expires (default 1 second)
        // In concurrent scenarios with 32 nodes, this would be 3.2GB
    }
}
```

## Notes

**Critical Limitation:** Upon closer examination of the Aptos bug bounty scope, this vulnerability may **not qualify** as a valid submission because:

1. **Component Scope**: The bug bounty explicitly focuses on "consensus, execution, storage, governance, and staking components" - the node-checker is a monitoring tool, not a blockchain component

2. **DoS Exclusion**: "Network-level DoS attacks are out of scope per bug bounty rules" - while this is application-level memory exhaustion rather than network flooding, DoS attacks generally appear to be excluded

3. **Severity Mismatch**: The defined severity categories focus on impacts to validators, consensus, and funds. DoS of a monitoring tool doesn't fit these categories clearly

4. **Non-Critical Infrastructure**: The node-checker crashing doesn't affect blockchain operation, consensus, or user funds

While this is a **real implementation flaw** that should be fixed (adding size limits is a security best practice), it likely falls outside the scope of blockchain security vulnerabilities that the Aptos bug bounty program targets.

The issue would be more appropriately categorized as an **operational/infrastructure concern** rather than a blockchain security vulnerability.

### Citations

**File:** ecosystem/node-checker/src/provider/api_index.rs (L35-35)
```rust
    output_cache: Arc<OutputCache<IndexResponse>>,
```

**File:** ecosystem/node-checker/src/provider/cache.rs (L14-21)
```rust
pub struct OutputCache<T: Clone + Debug> {
    /// The cache TTL.
    pub cache_ttl: Duration,
    /// The last time the Provider was run.
    pub last_run: RwLock<Instant>,
    /// The output of the last run of the Provider.
    pub last_output: RwLock<Option<T>>,
}
```

**File:** ecosystem/node-checker/src/provider/cache.rs (L48-53)
```rust
        let mut last_output = self.last_output.write().await;
        let mut last_run = self.last_run.write().await;
        let new_output = func.await?;
        *last_output = Some(new_output.clone());
        *last_run = Instant::now();
        Ok(new_output)
```

**File:** api/types/src/index.rs (L14-29)
```rust
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, PoemObject, Serialize)]
pub struct IndexResponse {
    /// Chain ID of the current chain
    pub chain_id: u8,
    pub epoch: U64,
    pub ledger_version: U64,
    pub oldest_ledger_version: U64,
    pub ledger_timestamp: U64,
    pub node_role: RoleType,
    pub oldest_block_height: U64,
    pub block_height: U64,
    // This must be optional to be backwards compatible
    /// Git hash of the build of the API endpoint.  Can be used to determine the exact
    /// software version used by the API endpoint.
    pub git_hash: Option<String>,
}
```

**File:** crates/aptos-rest-client/src/lib.rs (L1683-1685)
```rust
    async fn get<T: DeserializeOwned>(&self, url: Url) -> AptosResult<Response<T>> {
        self.json(self.inner.get(url).send().await?).await
    }
```

**File:** ecosystem/node-checker/src/runner/sync_runner.rs (L123-127)
```rust
            let api_index_provider = Arc::new(ApiIndexProvider::new(
                self.provider_configs.api_index.clone(),
                api_client,
            ));
            provider_collection.target_api_index_provider = Some(api_index_provider.clone());
```
