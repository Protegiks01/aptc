# Audit Report

## Title
Test Environment Leakage: FakeFunder Can Be Accidentally Deployed to Production Faucet Services Without Validation

## Summary
The `FakeFunder` implementation, designed solely for testing purposes, can be accidentally deployed to production faucet environments due to missing configuration validation. When active, it silently accepts all funding requests and returns success responses with empty transaction arrays, causing users to believe they received funds while no actual on-chain transfers occur.

## Finding Description

The Aptos faucet service supports multiple funder implementations through the `FunderConfig` enum. The `FakeFunder` is a no-op test implementation that always succeeds but performs no actual funding. [1](#0-0) 

The critical issue lies in the configuration loading and instantiation process. When building a funder from YAML configuration, there is **no validation** to prevent `FakeFunder` from being used in production: [2](#0-1) 

The `FakeFunder` variant is simply wrapped and returned without any checks for:
- Chain ID (mainnet vs testnet vs devnet)
- Environment variables indicating production
- Configuration warnings or logging

Furthermore, `FakeFunder` inherits the default `is_healthy()` implementation that always returns healthy: [3](#0-2) 

This means the health check endpoint will pass even when `FakeFunder` is active: [4](#0-3) 

When funding requests are processed, the empty transaction vector is converted to an empty hash array and returned as a successful response: [5](#0-4) 

**Attack Scenario:**
1. Operator accidentally copies a test configuration file to production deployment
2. Configuration specifies `type: FakeFunder` instead of `type: MintFunder` or `type: TransferFunder`
3. Faucet service starts successfully, health checks pass
4. Users submit funding requests that return HTTP 200 with `{"txn_hashes": []}`
5. Users believe they received funds but checking on-chain shows no transactions
6. Issue may go undetected until users complain, as monitoring shows "successful" requests

## Impact Explanation

**Severity: High** (per Aptos Bug Bounty criteria for "API crashes" and "Significant protocol violations")

While the faucet is not a consensus-critical component, this vulnerability causes:

1. **Service Degradation**: The faucet service becomes non-functional but appears operational
2. **User Impact**: Developers/users on devnet/testnet cannot receive test funds for development
3. **Silent Failure**: No errors are logged, health checks pass, metrics show success
4. **Detection Difficulty**: The issue would only be discovered through user complaints or on-chain verification

Note: Mainnet explicitly does not have a faucet service, limiting impact to test networks. However, the faucet is critical infrastructure for developers building on Aptos. [6](#0-5) 

## Likelihood Explanation

**Likelihood: Medium**

This can occur through:
- Accidental use of test configuration in deployment pipelines
- Copy-paste errors when creating new environment configs
- Misconfigured CI/CD automation
- Developer testing with FakeFunder config that accidentally gets promoted

The likelihood is elevated because:
- Configuration is loaded from external YAML files with no runtime validation
- No warnings or logs distinguish FakeFunder from production funders
- Health checks provide false confidence that the service is working

## Recommendation

Implement validation in `FunderConfig::build()` to prevent FakeFunder usage in production contexts:

```rust
impl FunderConfig {
    pub async fn build(self) -> Result<Arc<Funder>> {
        match self {
            FunderConfig::FakeFunder(_) => {
                // Check if this is a production-like environment
                if let Ok(env) = std::env::var("FAUCET_ENV") {
                    if env == "production" || env == "prod" {
                        anyhow::bail!(
                            "FakeFunder cannot be used in production environments. \
                             This is a test-only implementation that does not fund accounts."
                        );
                    }
                }
                
                // Log a clear warning
                aptos_logger::warn!(
                    "USING FAKE FUNDER - This is a test implementation that \
                     returns empty transactions and does not fund accounts!"
                );
                
                Ok(Arc::new(Funder::from(FakeFunder)))
            },
            // ... rest of implementation
        }
    }
}
```

Additionally, override `is_healthy()` for `FakeFunder` to return a warning message:

```rust
impl FunderTrait for FakeFunder {
    async fn is_healthy(&self) -> FunderHealthMessage {
        FunderHealthMessage {
            can_process_requests: true,
            message: Some("WARNING: Using FakeFunder test implementation".to_string()),
        }
    }
    // ... rest of implementation
}
```

## Proof of Concept

Create a test configuration file `fake_funder_prod.yaml`:

```yaml
server_config:
  listen_address: "0.0.0.0"
  listen_port: 8081
  api_path_base: ""

metrics_server_config:
  disable: false
  listen_address: "0.0.0.0"
  listen_port: 9101

bypasser_configs: []

checker_configs: []

funder_config:
  type: FakeFunder

handler_config:
  use_helpful_errors: true
  return_rejections_early: false
  max_concurrent_requests: 100
```

Run the faucet service:
```bash
cargo run -p aptos-faucet-service -- run -c fake_funder_prod.yaml
```

Submit a funding request:
```bash
curl -X POST http://localhost:8081/fund \
  -H "Content-Type: application/json" \
  -d '{"address": "0x1234567890abcdef", "amount": 100000000}'
```

**Expected Result (Vulnerable):**
```json
{"txn_hashes": []}
```
- HTTP 200 response (success)
- Empty transaction hashes
- No actual funding occurred
- Health check at `/` returns `tap:ok`

**Expected Result (After Fix):**
- Service fails to start with error: "FakeFunder cannot be used in production environments"
- Or logs prominent warning visible in monitoring

## Notes

This vulnerability specifically targets the operational security of the faucet service infrastructure. While not affecting blockchain consensus directly, it represents a significant reliability and user trust issue for developer-facing services that are critical to the Aptos ecosystem's growth.

### Citations

**File:** crates/aptos-faucet/core/src/funder/fake.rs (L16-26)
```rust
impl FunderTrait for FakeFunder {
    async fn fund(
        &self,
        _amount: Option<u64>,
        _receiver_address: AccountAddress,
        _asset: Option<String>,
        _check_only: bool,
        _did_bypass_checkers: bool,
    ) -> Result<Vec<SignedTransaction>, AptosTapError> {
        Ok(vec![])
    }
```

**File:** crates/aptos-faucet/core/src/funder/mod.rs (L59-64)
```rust
    async fn is_healthy(&self) -> FunderHealthMessage {
        FunderHealthMessage {
            can_process_requests: true,
            message: None,
        }
    }
```

**File:** crates/aptos-faucet/core/src/funder/mod.rs (L81-98)
```rust
impl FunderConfig {
    pub async fn build(self) -> Result<Arc<Funder>> {
        match self {
            FunderConfig::FakeFunder(_) => Ok(Arc::new(Funder::from(FakeFunder))),
            FunderConfig::MintFunder(config) => Ok(Arc::new(Funder::from(
                config
                    .build_funder()
                    .await
                    .context("Failed to build MintFunder")?,
            ))),
            FunderConfig::TransferFunder(config) => Ok(Arc::new(Funder::from(
                config
                    .build_funder()
                    .await
                    .context("Failed to build TransferFunder")?,
            ))),
        }
    }
```

**File:** crates/aptos-faucet/core/src/endpoints/basic.rs (L46-72)
```rust
    async fn root(&self) -> poem::Result<PlainText<String>> {
        // Confirm that we haven't hit the max concurrent requests.
        if let Some(ref semaphore) = self.concurrent_requests_semaphore {
            if semaphore.available_permits() == 0 {
                return Err(poem::Error::from((
                    StatusCode::SERVICE_UNAVAILABLE,
                    anyhow::anyhow!("Server is overloaded"),
                )));
            }
        }

        // Confirm that the Funder is healthy.
        let funder_health = self.funder.is_healthy().await;
        if !funder_health.can_process_requests {
            return Err(poem::Error::from((
                StatusCode::SERVICE_UNAVAILABLE,
                anyhow::anyhow!(
                    "{}",
                    funder_health
                        .message
                        .unwrap_or_else(|| "Funder is unhealthy".to_string())
                ),
            )));
        }

        Ok(PlainText("tap:ok".to_string()))
    }
```

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L112-119)
```rust
        let txns = self
            .components
            .fund_inner(fund_request.0, source_ip, header_map, false, asset.0)
            .await?;
        Ok(Json(FundResponse {
            txn_hashes: get_hashes(&txns),
        }))
    }
```

**File:** crates/aptos/src/common/types.rs (L1698-1700)
```rust
                Some(Network::Mainnet) => {
                    Err(CliError::CommandArgumentError("There is no faucet for mainnet. Please create and fund the account by transferring funds from another account. If you are confident you want to use a faucet, set --faucet-url or add a faucet URL to .aptos/config.yaml for the current profile".to_string()))
                },
```
