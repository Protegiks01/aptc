# Audit Report

## Title
Memory Exhaustion DoS via Unbounded Module Pagination in REST API

## Summary
The `max_account_modules_page_size` configuration parameter lacks validation and defaults to an excessively high value (9999), allowing API requests without explicit limits to load thousands of large modules into memory simultaneously. This enables memory exhaustion attacks that can crash or severely degrade API server performance, affecting availability for all users.

## Finding Description

The vulnerability exists in the REST API's account module retrieval endpoint. When a user queries `/accounts/{address}/modules` without specifying a `limit` parameter, the system uses `max_account_modules_page_size` as the default limit for the number of modules to retrieve. [1](#0-0) 

The API configuration file sets this default to 9999 with no upper bound validation. [2](#0-1) 

The configuration sanitizer performs no validation on this parameter, allowing operators to set it to the maximum u16 value (65535) or leave it at the dangerous default. [3](#0-2) 

The `modules()` function uses `max_account_modules_page_size` as both the default AND maximum limit when calling `determine_limit()`. This means every API request without an explicit limit will attempt to fetch up to 9999 modules. [4](#0-3) 

The `get_modules_by_pagination()` function collects all modules into memory with no size checks or memory limits. With Move modules potentially reaching 65KB each (per bytecode verifier limits), a single request could load up to 650MB (9999 × 65KB) into memory.

**Attack Path:**

1. Attacker deploys hundreds to thousands of large Move modules to an account across multiple transactions (gas costs are one-time)
2. Attacker makes multiple concurrent requests to `/accounts/{address}/modules` without a `limit` parameter
3. Each request attempts to load all modules (up to 9999 by default) into memory
4. Multiple concurrent requests multiply memory consumption (e.g., 10 requests × 650MB = 6.5GB)
5. API server experiences memory exhaustion, triggering OOM killer or severe performance degradation
6. API becomes unresponsive, denying service to all legitimate users

**Broken Invariants:**
- **Resource Limits (Invariant #9)**: "All operations must respect gas, storage, and computational limits" - The API layer fails to enforce memory consumption limits for module retrieval operations.

## Impact Explanation

This vulnerability enables a Denial of Service attack against the REST API with the following impacts:

- **API Availability**: Memory exhaustion causes API crashes or severe slowdowns, denying service to all users
- **Scope**: Affects all nodes running the public REST API
- **Persistence**: Attack is sustainable - once modules are deployed, the attacker only needs to send HTTP requests
- **Amplification**: One deployed account can be used for unlimited DoS attacks

Per the Aptos Bug Bounty severity categories, this qualifies as **High Severity** because it causes "API crashes" and "Validator node slowdowns" (if validators run the API). The impact does not extend to consensus, funds, or blockchain state, limiting it to availability concerns at the API layer.

## Likelihood Explanation

**Likelihood: Medium to High**

**Attacker Requirements:**
- Ability to deploy Move modules (requires gas, but one-time cost)
- Knowledge of default API configuration
- Ability to make concurrent HTTP requests (trivial)

**Feasibility:**
- Deploying 1000+ modules is expensive but achievable (modules can be small, minimal gas)
- Default configuration (9999) is already vulnerable without any misconfiguration
- Attack scales with concurrent requests from multiple sources
- No authentication or rate limiting prevents exploitation

**Realistic Scenario:**
A motivated attacker could spend ~100-1000 APT on module deployments to create a permanent DoS vector against any API node with default configuration. The attack can be executed repeatedly with minimal cost after initial setup.

## Recommendation

**Immediate Fixes:**

1. **Add Configuration Validation:** [2](#0-1) 

Add validation in the `sanitize()` method to enforce a reasonable maximum:

```rust
// Validate max_account_modules_page_size is within safe bounds
if api_config.max_account_modules_page_size > 1000 {
    return Err(Error::ConfigSanitizerFailed(
        sanitizer_name,
        format!(
            "max_account_modules_page_size ({}) exceeds safe limit of 1000",
            api_config.max_account_modules_page_size
        ),
    ));
}
```

2. **Reduce Default Value:** [1](#0-0) 

Change the default from 9999 to a more conservative value:

```rust
const DEFAULT_MAX_ACCOUNT_MODULES_PAGE_SIZE: u16 = 100;
```

3. **Use Smaller Default in determine_limit():** [5](#0-4) 

Instead of using `max_account_modules_page_size` as both default and maximum, use a smaller default (e.g., 25) while keeping the configured max as the ceiling:

```rust
determine_limit(
    self.limit,
    25, // Use conservative default like other paginated endpoints
    max_account_modules_page_size, // Keep configured max as ceiling
    &self.latest_ledger_info,
)? as u64,
```

4. **Add Memory-Based Limits:**

Implement total response size limits in the module collection logic to abort if accumulated data exceeds a threshold (e.g., 10MB).

## Proof of Concept

**Setup:**
```rust
// 1. Deploy many modules to an account
// (simplified - in practice would deploy actual Move modules)
for i in 0..1000 {
    deploy_module(account, create_module_bytecode(i, 50_000)); // 50KB modules
}

// 2. Configure API with high limit
let mut api_config = ApiConfig::default();
api_config.max_account_modules_page_size = 9999;

// 3. Launch concurrent requests without limit parameter
let handles: Vec<_> = (0..20).map(|_| {
    tokio::spawn(async {
        client.get(&format!("/v1/accounts/{}/modules", account))
            .send()
            .await
    })
}).collect();

// Expected: API server memory usage spikes to multiple GB
// Expected: API becomes unresponsive or crashes with OOM
```

**Verification:**
1. Monitor API server memory usage before and during attack
2. Observe memory consumption exceeds available RAM
3. Confirm API returns 500 errors or times out
4. Verify legitimate API requests fail during attack

**Notes:**
The test environment would need sufficient resources to deploy many modules and stress-test the API. The exact number of modules and concurrent requests needed depends on available server memory, but the vulnerability is demonstrable with the default configuration.

### Citations

**File:** config/src/config/api_config.rs (L101-101)
```rust
const DEFAULT_MAX_ACCOUNT_MODULES_PAGE_SIZE: u16 = 9999;
```

**File:** config/src/config/api_config.rs (L163-200)
```rust
impl ConfigSanitizer for ApiConfig {
    fn sanitize(
        node_config: &NodeConfig,
        node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();
        let api_config = &node_config.api;

        // If the API is disabled, we don't need to do anything
        if !api_config.enabled {
            return Ok(());
        }

        // Verify that failpoints are not enabled in mainnet
        if let Some(chain_id) = chain_id {
            if chain_id.is_mainnet() && api_config.failpoints_enabled {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    "Failpoints are not supported on mainnet nodes!".into(),
                ));
            }
        }

        // Validate basic runtime properties
        if api_config.max_runtime_workers.is_none() && api_config.runtime_worker_multiplier == 0 {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "runtime_worker_multiplier must be greater than 0!".into(),
            ));
        }

        // Sanitize the gas estimation config
        GasEstimationConfig::sanitize(node_config, node_type, chain_id)?;

        Ok(())
    }
}
```

**File:** api/src/accounts.rs (L518-532)
```rust
    pub fn modules(self, accept_type: &AcceptType) -> BasicResultWith404<Vec<MoveModuleBytecode>> {
        let max_account_modules_page_size = self.context.max_account_modules_page_size();
        let (modules, next_state_key) = self
            .context
            .get_modules_by_pagination(
                self.address.into(),
                self.start.as_ref(),
                self.ledger_version,
                // Just use the max as the default
                determine_limit(
                    self.limit,
                    max_account_modules_page_size,
                    max_account_modules_page_size,
                    &self.latest_ledger_info,
                )? as u64,
```

**File:** api/src/context.rs (L605-609)
```rust
            .take(limit as usize + 1);
        let kvs = module_iter
            .by_ref()
            .take(limit as usize)
            .collect::<Result<_>>()?;
```
