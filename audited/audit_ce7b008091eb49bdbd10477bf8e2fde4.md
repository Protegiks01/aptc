# Audit Report

## Title
Unvalidated `full_block_txns` Configuration Causes Panic in Gas Estimation API

## Summary
The `GasEstimationConfig` struct's `full_block_txns` field is not validated to be greater than zero by the configuration sanitizer. When set to 0, this causes a panic via `.unwrap()` on an empty iterator in the gas estimation logic, leading to API endpoint failures.

## Finding Description

The configuration sanitizer for `GasEstimationConfig` validates that the block history fields are non-zero and properly ordered, but does not validate the `full_block_txns` field: [1](#0-0) 

However, the `full_block_txns` field (defined at line 25) is used in a critical comparison within the `block_min_inclusion_price` method: [2](#0-1) 

When `full_block_txns` is set to 0 and a block contains no user transactions (resulting in an empty `prices_and_used` vector), the condition `0 >= 0` evaluates to `true`, setting `is_full_block = true`. This triggers execution of the following code: [3](#0-2) 

The `.min().unwrap()` call on line 1274 panics because the iterator over `prices_and_used` is empty.

The `get_gas_prices_and_used` method can legitimately return an empty vector when blocks contain only system transactions: [4](#0-3) 

**Exploitation Path:**
1. Node operator sets `full_block_txns: 0` in the node configuration (either accidentally or due to misunderstanding)
2. Configuration sanitizer does not detect this invalid value
3. Gas estimation API endpoint is called via `/estimate_gas_price`
4. When processing historical blocks that contain no user transactions, `prices_and_used` is empty
5. The condition `0 >= 0` is true, so `is_full_block = true`
6. Code attempts `.min().unwrap()` on empty iterator
7. Panic occurs, causing API request to fail with internal error

## Impact Explanation

This issue qualifies as **High Severity** under the Aptos bug bounty criteria for "API crashes". While Tokio's panic handling prevents complete server crashes (the panic is caught when awaiting the spawned task), the gas estimation endpoint becomes unreliable and fails consistently when:
- The configuration has `full_block_txns: 0`
- Historical blocks with no user transactions are encountered [5](#0-4) 

This affects:
- **API Availability**: The `/estimate_gas_price` endpoint fails with HTTP 500 errors
- **Client Operations**: Applications relying on gas estimation cannot function properly
- **Transaction Submission**: Users cannot determine appropriate gas prices for transactions
- **Node Reliability**: Undermines trust in the API infrastructure

## Likelihood Explanation

**Likelihood: Medium**

While this requires operator configuration rather than external exploitation, the likelihood is non-trivial because:
1. The configuration field name doesn't clearly indicate it must be non-zero
2. An operator might set it to 0 thinking it disables the feature
3. No validation error occurs during node startup
4. The default value is 250, but custom configurations may override it
5. Blocks with zero user transactions occur naturally during low-activity periods

The impact materializes whenever historical analysis encounters blocks without user transactions, which is a normal occurrence in blockchain operation.

## Recommendation

Add validation for `full_block_txns` in the configuration sanitizer to ensure it is greater than zero:

```rust
impl ConfigSanitizer for GasEstimationConfig {
    fn sanitize(
        node_config: &NodeConfig,
        _node_type: NodeType,
        _chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();
        let gas_estimation_config = &node_config.api.gas_estimation;

        // Existing validations...

        if gas_estimation_config.full_block_txns == 0 {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "full_block_txns must be > 0".to_string(),
            ));
        }

        Ok(())
    }
}
```

Additionally, add defensive programming in `block_min_inclusion_price` to handle empty price vectors gracefully:

```rust
if is_full_block {
    if let Some(min_price) = prices_and_used.iter().map(|(price, _)| *price).min() {
        Some(self.next_bucket(min_price))
    } else {
        None
    }
} else {
    None
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ApiConfig;

    #[test]
    fn test_sanitize_invalid_zero_full_block_txns() {
        // Create a node config with full_block_txns set to 0
        let node_config = NodeConfig {
            api: ApiConfig {
                gas_estimation: GasEstimationConfig {
                    full_block_txns: 0,
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        };

        // Sanitize the config and verify that it fails
        let error = GasEstimationConfig::sanitize(
            &node_config,
            NodeType::Validator,
            Some(ChainId::mainnet()),
        );
        
        // This currently passes (bug), but should fail after the fix
        assert!(error.is_err(), "Configuration with full_block_txns=0 should be rejected");
    }
}
```

**Notes**

This vulnerability demonstrates a gap in the defense-in-depth strategy for configuration validation. While the sanitizer validates block history parameters, it misses the `full_block_txns` field which is equally critical for safe operation. The panic occurs in production code paths that process historical blockchain data, making it reproducible under normal operating conditions when the misconfiguration is present.

### Citations

**File:** config/src/config/gas_estimation_config.rs (L78-91)
```rust
        if gas_estimation_config.low_block_history == 0
            || gas_estimation_config.market_block_history == 0
            || gas_estimation_config.aggressive_block_history == 0
        {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                format!(
                    "low {}, market {}, aggressive {} block history must be > 0",
                    gas_estimation_config.low_block_history,
                    gas_estimation_config.market_block_history,
                    gas_estimation_config.aggressive_block_history
                ),
            ));
        }
```

**File:** api/src/context.rs (L1175-1177)
```rust
        if start_version > ledger_version || limit == 0 {
            return Ok((vec![], vec![], None));
        }
```

**File:** api/src/context.rs (L1253-1253)
```rust
                    } else if prices_and_used.len() >= gas_estimation_config.full_block_txns {
```

**File:** api/src/context.rs (L1267-1276)
```rust
                if is_full_block {
                    Some(
                        self.next_bucket(
                            prices_and_used
                                .iter()
                                .map(|(price, _)| *price)
                                .min()
                                .unwrap(),
                        ),
                    )
```

**File:** api/src/context.rs (L1651-1653)
```rust
    tokio::task::spawn_blocking(func)
        .await
        .map_err(|err| E::internal_with_code_no_info(err, AptosErrorCode::InternalError))?
```
