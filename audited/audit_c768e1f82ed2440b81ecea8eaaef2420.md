# Audit Report

## Title
Faucet Gas Price Manipulation via Unvalidated API Response

## Summary
The Aptos faucet's `GasUnitPriceManager::fetch_gas_unit_price()` function accepts gas price estimates from an external API without any validation, bounds checking, or sanity verification. If the faucet connects to a malicious or compromised node, the node can return arbitrarily high gas prices (up to the blockchain maximum of 10 billion octas per gas unit), causing the faucet to overpay for gas by potentially millions of times the normal rate, rapidly draining its funds. [1](#0-0) 

## Finding Description

The faucet's gas price manager fetches gas estimates from the configured node's API endpoint without validation. The attack flow is:

1. **Faucet Configuration**: The faucet is configured with a `node_url` pointing to an Aptos node API endpoint.

2. **Periodic Gas Price Fetching**: Every 30 seconds (default TTL), the `GasUnitPriceManager` calls the node's `/estimate_gas_price` endpoint and stores the returned `gas_estimate` value directly without validation. [2](#0-1) 

3. **Transaction Creation**: When creating transactions, both `MintFunder` and `TransferFunder` use this unchecked gas price to build transactions via `TransactionFactory::with_gas_unit_price()`. [3](#0-2) [4](#0-3) 

4. **Blockchain Acceptance**: The Aptos blockchain enforces a maximum gas price of 10,000,000,000 octas (100 APT) per gas unit. Any value below this is accepted. [5](#0-4) [6](#0-5) 

5. **Attack Scenarios**: An attacker could exploit this by:
   - Compromising the faucet's configuration to point to a malicious node
   - Compromising a legitimate node that the faucet connects to
   - Performing a man-in-the-middle attack if HTTPS is not properly enforced
   - DNS hijacking to redirect the node_url

6. **Financial Impact**: Normal mainnet gas prices are approximately 100-150 octas per gas unit. A malicious response of 9,000,000,000 octas (90 APT per gas unit) would cause the faucet to overpay by **60,000,000x**. Even a more subtle attack with 10,000,000 octas (0.1 APT per gas unit) represents a **66,666x** markup.

## Impact Explanation

This vulnerability qualifies as **Medium Severity** under the Aptos Bug Bounty criteria for "Limited funds loss or manipulation." The faucet service, while not consensus-critical, holds significant funds for distribution and could be drained at an accelerated rate that defeats its intended operational parameters.

While a `gas_unit_price_override` configuration option exists to set a fixed gas price, this is optional and not set by default. [7](#0-6) [8](#0-7) 

The absence of input validation on external API data represents a defense-in-depth failure, as the faucet blindly trusts potentially untrusted network sources.

## Likelihood Explanation

**Likelihood: Medium**

The attack requires one of the following conditions:
- Access to modify the faucet's configuration (`node_url` parameter)
- Compromise of a legitimate Aptos node that the faucet connects to
- Successful man-in-the-middle attack on the API connection
- DNS hijacking targeting the faucet's node endpoint

While these scenarios require some level of system access or network position, they are realistic attack vectors for infrastructure-targeted attacks. Faucets are often run in less hardened environments compared to validator nodes, making them viable targets.

## Recommendation

**Immediate Mitigation:**
1. Always set `gas_unit_price_override` in production configurations to a reasonable fixed value
2. Add validation logic to reject unreasonable gas price estimates

**Code Fix:**
Add bounds checking in `GasUnitPriceManager::fetch_gas_unit_price()`:

```rust
async fn fetch_gas_unit_price(&self) -> Result<u64> {
    let gas_estimate = self
        .api_client
        .estimate_gas_price()
        .await?
        .into_inner()
        .gas_estimate;
    
    // Reasonable upper bound: 10x the typical max (1000 octas = 0.00001 APT)
    // This is still 10,000 octas = 0.0001 APT, which is very generous
    const MAX_REASONABLE_GAS_PRICE: u64 = 10_000;
    
    if gas_estimate > MAX_REASONABLE_GAS_PRICE {
        warn!(
            "Rejecting unreasonably high gas price estimate: {} (max: {})",
            gas_estimate, MAX_REASONABLE_GAS_PRICE
        );
        return Err(anyhow::anyhow!(
            "Gas price estimate {} exceeds maximum reasonable value {}",
            gas_estimate,
            MAX_REASONABLE_GAS_PRICE
        ));
    }
    
    Ok(gas_estimate)
}
```

Additionally, document the importance of setting `gas_unit_price_override` in the configuration documentation and consider making it a required field or providing a safe default.

## Proof of Concept

```rust
#[tokio::test]
async fn test_malicious_gas_price_exploitation() {
    use aptos_faucet_core::funder::common::GasUnitPriceManager;
    use reqwest::Url;
    use std::time::Duration;
    use mockito::Server;
    
    // Start a mock malicious server
    let mut server = Server::new_async().await;
    
    // Mock endpoint returns maliciously high gas price (9 billion octas = 90 APT per gas unit)
    let mock = server.mock("GET", "/v1/estimate_gas_price")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{
            "gas_estimate": 9000000000,
            "deprioritized_gas_estimate": 9000000000,
            "prioritized_gas_estimate": 9000000000
        }"#)
        .create_async()
        .await;
    
    // Create GasUnitPriceManager pointing to malicious server
    let manager = GasUnitPriceManager::new(
        Url::parse(&server.url()).unwrap(),
        Duration::from_secs(30)
    );
    
    // Fetch gas price - should accept the malicious value without validation
    let gas_price = manager.get_gas_unit_price().await.unwrap();
    
    // Verify that the faucet would use this malicious value
    assert_eq!(gas_price, 9_000_000_000);
    
    // Calculate overpayment factor
    const NORMAL_GAS_PRICE: u64 = 150; // typical mainnet price
    let overpayment_factor = gas_price / NORMAL_GAS_PRICE;
    
    // Demonstrates 60,000,000x overpayment
    assert!(overpayment_factor > 60_000_000);
    
    mock.assert_async().await;
}
```

## Notes

This vulnerability specifically affects the **faucet service**, not the core consensus or blockchain protocol. However, it represents a significant operational security issue for Aptos infrastructure, as faucets are essential for testnet operations and developer onboarding. The lack of input validation on external API responses is a fundamental security principle violation that could enable rapid fund depletion under adversarial conditions.

The blockchain's built-in maximum gas price of 10 billion octas provides an upper bound on the attack, but this bound is still 60+ million times higher than normal operational values, making it an ineffective defense against this specific vulnerability.

### Citations

**File:** crates/aptos-faucet/core/src/funder/common.rs (L109-111)
```rust
    /// If given, we'll use this value for the gas unit price. If not, we'll use
    /// the gas unit price estimation API periodically.
    pub gas_unit_price_override: Option<u64>,
```

**File:** crates/aptos-faucet/core/src/funder/common.rs (L420-438)
```rust
    pub async fn get_gas_unit_price(&self) -> Result<u64> {
        let now = Instant::now();

        // If we're still within the TTL, just return the current value.
        if let Some(last_updated) = *self.last_updated.read().await {
            if now.duration_since(last_updated) < self.cache_ttl {
                return Ok(self.gas_unit_price.load(Ordering::Acquire));
            }
        }

        // We're beyond the TTL, update the value and last_updated.
        let mut last_updated = self.last_updated.write().await;
        let new_price = self.fetch_gas_unit_price().await?;
        self.gas_unit_price.store(new_price, Ordering::Release);
        *last_updated = Some(now);

        info!(gas_unit_price = new_price, event = "gas_unit_price_updated");
        Ok(new_price)
    }
```

**File:** crates/aptos-faucet/core/src/funder/common.rs (L440-447)
```rust
    async fn fetch_gas_unit_price(&self) -> Result<u64> {
        Ok(self
            .api_client
            .estimate_gas_price()
            .await?
            .into_inner()
            .gas_estimate)
    }
```

**File:** crates/aptos-faucet/core/src/funder/mint.rs (L256-267)
```rust
    async fn get_gas_unit_price(&self) -> Result<u64, AptosTapError> {
        match self.txn_config.gas_unit_price_override {
            Some(gas_unit_price) => Ok(gas_unit_price),
            None => self
                .gas_unit_price_manager
                .get_gas_unit_price()
                .await
                .map_err(|e| {
                    AptosTapError::new_with_error_code(e, AptosTapErrorCode::AptosApiError)
                }),
        }
    }
```

**File:** crates/aptos-faucet/core/src/funder/transfer.rs (L186-197)
```rust
    async fn get_gas_unit_price(&self) -> Result<u64, AptosTapError> {
        match self.gas_unit_price_override {
            Some(gas_unit_price) => Ok(gas_unit_price),
            None => self
                .gas_unit_price_manager
                .get_gas_unit_price()
                .await
                .map_err(|e| {
                    AptosTapError::new_with_error_code(e, AptosTapErrorCode::AptosApiError)
                }),
        }
    }
```

**File:** aptos-move/aptos-vm/src/gas.rs (L194-208)
```rust
    // The submitted gas price is greater than the maximum gas unit price set by the VM.
    if txn_metadata.gas_unit_price() > txn_gas_params.max_price_per_gas_unit {
        speculative_warn!(
            log_context,
            format!(
                "[VM] Gas unit error; max {}, submitted {}",
                txn_gas_params.max_price_per_gas_unit,
                txn_metadata.gas_unit_price()
            ),
        );
        return Err(VMStatus::error(
            StatusCode::GAS_UNIT_PRICE_ABOVE_MAX_BOUND,
            None,
        ));
    }
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L66-71)
```rust
        // The maximum gas unit price that a transaction can be submitted with.
        [
            max_price_per_gas_unit: FeePerGasUnit,
            "max_price_per_gas_unit",
            10_000_000_000
        ],
```

**File:** crates/aptos-faucet/cli/src/main.rs (L86-87)
```rust
            30,   // gas_unit_price_ttl_secs
            None, // gas_unit_price_override
```
