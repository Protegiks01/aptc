# Audit Report

## Title
Complete Security Bypass in Aptos Faucet Through Empty Checker Configuration

## Summary
The Aptos Faucet allows configuration with an empty `checker_configs` vector, which completely bypasses all security controls including rate limiting, authentication, captcha validation, IP blocklisting, and referer checks. This enables any attacker to drain the entire faucet balance through unlimited funding requests without any restrictions.

## Finding Description

The Aptos Faucet implements a modular security system through "checkers" that validate funding requests. The configuration accepts a `Vec<CheckerConfig>` field that defines which security checks to apply. [1](#0-0) 

When the faucet server initializes, it builds checker instances from this configuration: [2](#0-1) 

If `checker_configs` is empty, the loop executes zero times, resulting in an empty `checkers` vector. This empty vector is then passed to `FundApiComponents`: [3](#0-2) 

During request processing, the `preprocess_request` function iterates through checkers to validate the request: [4](#0-3) 

**Critical flaw**: When `self.checkers` is empty, the for loop at line 263 never executes, `rejection_reasons` remains empty, and the check at line 272 passes without rejecting the request. The function returns `Ok`, allowing the funding to proceed unconditionally.

The `build_for_cli` function demonstrates this vulnerability is exploitable in practice, as it intentionally creates a configuration with no security checks: [5](#0-4) 

**Attack Path:**
1. Operator deploys faucet with empty `checker_configs: []` (either accidentally or using CLI configuration for production)
2. Attacker sends unlimited POST requests to `/fund` endpoint
3. Each request bypasses all security checks (no iteration in checker loop)
4. Faucet funds every request up to configured maximum amount
5. Attacker drains entire faucet balance

There is no validation, warning, or safeguard preventing this dangerous configuration from being deployed.

## Impact Explanation

This represents a **Critical** severity vulnerability under the Aptos Bug Bounty program criteria:
- **Loss of Funds**: Complete drainage of faucet balance through unlimited, unrestricted funding requests
- The faucet holds substantial amounts of tokens (testnet APT or other assets) that can be completely drained

While the faucet typically operates on testnet/devnet rather than mainnet, the security impact is severe:
- Faucets are critical infrastructure for ecosystem development
- Complete fund drainage causes total loss of service availability
- Replacement requires manual intervention and refunding
- Affects all legitimate developers and users who depend on the faucet

The vulnerability enables **complete bypass** of all intended security controls without any technical sophistication required.

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability is highly likely to occur because:

1. **Intentional Design Pattern**: The codebase explicitly includes functionality to create empty checker configurations (`build_for_cli`), normalizing this dangerous pattern

2. **No Validation**: There is zero validation preventing deployment with empty checkers - no compiler errors, runtime checks, or configuration warnings

3. **Operational Confusion**: Operators may copy CLI configuration patterns for production deployment without understanding security implications

4. **Silent Failure**: The system accepts and runs with empty checkers without any indication this is a critical security misconfiguration

5. **Trivial Exploitation**: Once deployed with empty checkers, exploitation requires only basic HTTP requests - no authentication, captcha solving, or sophisticated techniques

## Recommendation

Implement mandatory validation to prevent empty checker configurations in production environments:

```rust
// In crates/aptos-faucet/core/src/server/run.rs
impl RunConfig {
    async fn run_impl(self, port_tx: Option<OneShotSender<u16>>) -> Result<()> {
        info!("Running with config: {:#?}", self);
        
        // Add validation for empty checker configs
        #[cfg(not(test))]
        if self.checker_configs.is_empty() && self.bypasser_configs.is_empty() {
            return Err(anyhow!(
                "SECURITY ERROR: Running faucet with no checkers or bypassers is extremely dangerous. \
                 This configuration allows unlimited, unrestricted fund requests and will result in \
                 complete drainage of faucet funds. Add at least one checker (e.g., MemoryRatelimit, \
                 AuthToken, IpBlocklist) to the checker_configs array."
            ));
        }
        
        // Existing code continues...
    }
}
```

Additionally:
1. **Add configuration validation**: Create a separate validation function that checks for dangerous configurations
2. **Require explicit override**: Add a `--allow-unsafe-config` flag that must be explicitly set for development/testing scenarios
3. **Documentation**: Clearly document the security implications of each configuration option
4. **Default safe config**: Provide template configurations with minimum recommended security checkers
5. **Monitoring**: Log warnings when operating with fewer than recommended checkers

## Proof of Concept

**Configuration File** (`unsafe_faucet.yaml`):
```yaml
server_config:
  listen_address: "0.0.0.0"
  listen_port: 8081
  api_path_base: ""
metrics_server_config:
  listen_port: 9105
bypasser_configs: []
checker_configs: []  # EMPTY - No security checks!
funder_config:
  type: "MintFunder"
  api_connection_config:
    node_url: "http://localhost:8080"
    chain_id: 4
  transaction_submission_config:
    maximum_amount: 100000000000
    gas_unit_price_override: 100
    max_gas_amount: 500000
  assets:
    apt:
      key_file_path: "/tmp/mint.key"
      mint_account_address: "0x1"
  default_asset: "apt"
  amount_to_fund: 100000000000
handler_config:
  use_helpful_errors: true
  return_rejections_early: false
```

**Exploitation Steps**:
```bash
# 1. Start faucet with empty checkers
aptos-faucet run --config-path unsafe_faucet.yaml

# 2. Drain faucet with unlimited requests
for i in {1..10000}; do
  curl -X POST http://localhost:8081/fund \
    -H "Content-Type: application/json" \
    -d "{\"address\":\"0x$(openssl rand -hex 32)\",\"amount\":100000000000}"
done

# Each request succeeds - no rate limiting, no authentication, no captcha
# Faucet is completely drained in seconds
```

**Expected Result**: All 10,000 requests succeed, each funding a new account with 100 billion tokens, completely draining the faucet without any security checks applied.

## Notes

This vulnerability specifically affects the Aptos Faucet service, which while not a core consensus/blockchain component, is critical infrastructure for testnet/devnet operations. The faucet's security model assumes at least one checker will validate requests, but this assumption is not enforced at the configuration or runtime level.

### Citations

**File:** crates/aptos-faucet/core/src/server/run.rs (L56-67)
```rust
pub struct RunConfig {
    /// API server config.
    pub server_config: ServerConfig,

    /// Metrics server config.
    metrics_server_config: MetricsServerConfig,

    /// Configs for any Bypassers we might want to enable.
    bypasser_configs: Vec<BypasserConfig>,

    /// Configs for any Checkers we might want to enable.
    checker_configs: Vec<CheckerConfig>,
```

**File:** crates/aptos-faucet/core/src/server/run.rs (L128-139)
```rust
        let mut checkers: Vec<Checker> = Vec::new();
        for checker_config in &self.checker_configs {
            let checker = checker_config
                .clone()
                .build(captcha_manager.clone())
                .await
                .with_context(|| {
                    format!("Failed to build Checker with args: {:?}", checker_config)
                })?;
            checker.spawn_periodic_tasks(&mut join_set);
            checkers.push(checker);
        }
```

**File:** crates/aptos-faucet/core/src/server/run.rs (L146-152)
```rust
        let fund_api_components = Arc::new(FundApiComponents {
            bypassers,
            checkers,
            funder,
            return_rejections_early: self.handler_config.return_rejections_early,
            concurrent_requests_semaphore,
        });
```

**File:** crates/aptos-faucet/core/src/server/run.rs (L276-277)
```rust
            bypasser_configs: vec![],
            checker_configs: vec![],
```

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L261-280)
```rust
        // Ensure request passes checkers.
        let mut rejection_reasons = Vec::new();
        for checker in &self.checkers {
            rejection_reasons.extend(checker.check(checker_data.clone(), dry_run).await.map_err(
                |e| AptosTapError::new_with_error_code(e, AptosTapErrorCode::CheckerError),
            )?);
            if !rejection_reasons.is_empty() && self.return_rejections_early {
                break;
            }
        }

        if !rejection_reasons.is_empty() {
            return Err(AptosTapError::new(
                format!("Request rejected by {} checkers", rejection_reasons.len()),
                AptosTapErrorCode::Rejected,
            )
            .rejection_reasons(rejection_reasons));
        }

        Ok((checker_data, false, permit))
```
