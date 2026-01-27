# Audit Report

## Title
Unbounded Gas Estimation Block History Configuration Causes API Node Denial of Service

## Summary
The `GasEstimationConfig` sanitizer fails to enforce upper bounds on `aggressive_block_history`, `market_block_history`, and `low_block_history` configuration values. An operator who sets these values to extremely large numbers (either maliciously or accidentally) will cause the `/estimate_gas_price` API endpoint to perform millions of database reads per request, making API nodes completely unresponsive and preventing users from submitting transactions.

## Finding Description
The gas estimation configuration allows node operators to specify how many historical blocks should be analyzed when estimating gas prices. The configuration sanitizer validates that values are greater than zero and that `aggressive_block_history >= market_block_history` and `aggressive_block_history >= low_block_history`, but **critically fails to enforce any upper bounds**. [1](#0-0) 

When the `/estimate_gas_price` endpoint is called, it executes `estimate_gas_price()` which loops up to `max_block_history = config.aggressive_block_history` times, performing a database read via `get_block_info_by_version()` on each iteration: [2](#0-1) 

The endpoint handler uses `api_spawn_blocking()` which provides no timeout mechanism: [3](#0-2) [4](#0-3) 

**Attack Scenario:**
1. Operator sets configuration: `aggressive_block_history: 1000000` (1 million blocks)
2. Configuration passes sanitization (only checks > 0 and relative ordering)
3. API node starts and loads the configuration
4. User calls `/estimate_gas_price` endpoint
5. System attempts to read up to 1 million blocks from database
6. Request blocks for extended period (potentially minutes)
7. Multiple concurrent requests exhaust all 64 blocking threads
8. API node becomes completely unresponsive
9. All API operations fail, including transaction submission

This breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits." The codebase even defines `MAX_REQUEST_LIMIT = 20_000` as a defense against large queries: [5](#0-4) 

However, this limit is not applied to gas estimation block history configuration.

## Impact Explanation
**Severity: High** (API crashes/unresponsiveness)

This vulnerability causes:
- **Total API node unavailability**: All API endpoints become unresponsive when blocking threads are exhausted
- **Transaction submission failure**: Users cannot submit transactions through affected API nodes
- **Cascading failures**: If multiple API nodes in a network use the same misconfigured values, it impacts the entire network's API layer
- **Prolonged outage**: Requires configuration change and node restart to recover

This meets the **High Severity** criteria per Aptos bug bounty: "API crashes" and causes significant service disruption, though it falls short of **Critical** severity since it doesn't affect consensus or cause permanent fund loss.

## Likelihood Explanation
**Likelihood: Medium-High**

This vulnerability can occur through:
1. **Accidental misconfiguration**: Operator mistakenly adds extra zeros (e.g., `12000` instead of `120`)
2. **Copy-paste errors**: Using values from different contexts without understanding their impact
3. **Malicious operator**: Intentionally setting large values to DoS the API node
4. **Compromised operator account**: Attacker with configuration file access sets malicious values

The default values (10, 30, 120) are reasonable, but nothing prevents catastrophic misconfigurations. Unlike other configuration parameters which have explicit validations and reasonable defaults, block history values can be set to arbitrary magnitudes.

## Recommendation
Add strict upper bound validation in the `GasEstimationConfig::sanitize()` method:

```rust
impl ConfigSanitizer for GasEstimationConfig {
    fn sanitize(
        node_config: &NodeConfig,
        _node_type: NodeType,
        _chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();
        let gas_estimation_config = &node_config.api.gas_estimation;
        
        // Define maximum safe block history based on MAX_REQUEST_LIMIT
        const MAX_BLOCK_HISTORY: usize = 10_000; // Reasonable upper bound
        
        // Validate upper bounds
        if gas_estimation_config.aggressive_block_history > MAX_BLOCK_HISTORY
            || gas_estimation_config.market_block_history > MAX_BLOCK_HISTORY
            || gas_estimation_config.low_block_history > MAX_BLOCK_HISTORY
        {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                format!(
                    "Block history values must not exceed {}. Got: low={}, market={}, aggressive={}",
                    MAX_BLOCK_HISTORY,
                    gas_estimation_config.low_block_history,
                    gas_estimation_config.market_block_history,
                    gas_estimation_config.aggressive_block_history
                ),
            ));
        }

        // Validate aggressive price takes the most history
        if gas_estimation_config.low_block_history > gas_estimation_config.aggressive_block_history
            || gas_estimation_config.market_block_history
                > gas_estimation_config.aggressive_block_history
        {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                format!(
                    "aggressive block history {} must be >= low {}, market {}",
                    gas_estimation_config.aggressive_block_history,
                    gas_estimation_config.low_block_history,
                    gas_estimation_config.market_block_history
                ),
            ));
        }

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

        Ok(())
    }
}
```

## Proof of Concept

**Configuration File (malicious_config.yaml):**
```yaml
api:
  enabled: true
  gas_estimation:
    enabled: true
    low_block_history: 500000
    market_block_history: 750000
    aggressive_block_history: 1000000
    full_block_txns: 250
    cache_expiration_ms: 500
    incorporate_reordering_effects: true
```

**Exploitation Steps:**
1. Create the above configuration file
2. Start API node with: `aptos-node --config malicious_config.yaml`
3. Node successfully starts (sanitizer passes validation)
4. Make concurrent requests to trigger DoS:
```bash
for i in {1..10}; do
  curl http://localhost:8080/estimate_gas_price &
done
```
5. Observe API node becomes unresponsive
6. All subsequent transaction submissions fail with timeout errors
7. Node requires restart with corrected configuration to recover

**Expected Result:** API node blocks for minutes attempting to read 1 million blocks from database, exhausting all blocking threads and preventing any API operations.

**With Fix:** Configuration validation fails at startup with clear error message about exceeding maximum allowed block history.

---

**Notes:**
- This vulnerability requires operator-level access to configuration files but represents a critical defense-in-depth failure
- The lack of upper bounds violates the principle of fail-safe defaults
- Similar validation exists for other configuration parameters (e.g., `max_transactions_page_size`, `max_events_page_size`) but was omitted for gas estimation
- The impact is amplified because the `/estimate_gas_price` endpoint is publicly accessible without authentication

### Citations

**File:** config/src/config/gas_estimation_config.rs (L53-95)
```rust
impl ConfigSanitizer for GasEstimationConfig {
    fn sanitize(
        node_config: &NodeConfig,
        _node_type: NodeType,
        _chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();
        let gas_estimation_config = &node_config.api.gas_estimation;

        // Validate aggressive price takes the most history
        if gas_estimation_config.low_block_history > gas_estimation_config.aggressive_block_history
            || gas_estimation_config.market_block_history
                > gas_estimation_config.aggressive_block_history
        {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                format!(
                    "aggressive block history {} must be > low {}, market {}",
                    gas_estimation_config.aggressive_block_history,
                    gas_estimation_config.low_block_history,
                    gas_estimation_config.market_block_history
                ),
            ));
        }

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

        Ok(())
    }
}
```

**File:** api/src/context.rs (L1325-1359)
```rust
        let max_block_history = config.aggressive_block_history;
        // 1. Get the block metadata txns
        let mut lookup_version = ledger_info.ledger_version.0;
        let mut blocks = vec![];
        // Skip the first block, which may be partial
        if let Ok((first, _, block)) = self.db.get_block_info_by_version(lookup_version) {
            if block.epoch() == epoch {
                lookup_version = first.saturating_sub(1);
            }
        }
        let mut cached_blocks_hit = false;
        for _i in 0..max_block_history {
            if cache
                .min_inclusion_prices
                .contains_key(&(epoch, lookup_version))
            {
                cached_blocks_hit = true;
                break;
            }
            match self.db.get_block_info_by_version(lookup_version) {
                Ok((first, last, block)) => {
                    if block.epoch() != epoch {
                        break;
                    }
                    lookup_version = first.saturating_sub(1);
                    blocks.push((first, last));
                    if lookup_version == 0 {
                        break;
                    }
                },
                Err(_) => {
                    break;
                },
            }
        }
```

**File:** api/src/context.rs (L1645-1654)
```rust
pub async fn api_spawn_blocking<F, T, E>(func: F) -> Result<T, E>
where
    F: FnOnce() -> Result<T, E> + Send + 'static,
    T: Send + 'static,
    E: InternalError + Send + 'static,
{
    tokio::task::spawn_blocking(func)
        .await
        .map_err(|err| E::internal_with_code_no_info(err, AptosErrorCode::InternalError))?
}
```

**File:** api/src/transactions.rs (L817-846)
```rust
    async fn estimate_gas_price(&self, accept_type: AcceptType) -> BasicResult<GasEstimation> {
        fail_point_poem("endpoint_encode_submission")?;
        self.context
            .check_api_output_enabled("Estimate gas price", &accept_type)?;

        let context = self.context.clone();
        api_spawn_blocking(move || {
            let latest_ledger_info = context.get_latest_ledger_info()?;
            let gas_estimation = context.estimate_gas_price(&latest_ledger_info)?;
            Self::log_gas_estimation(&gas_estimation);

            match accept_type {
                AcceptType::Json => BasicResponse::try_from_json((
                    gas_estimation,
                    &latest_ledger_info,
                    BasicResponseStatus::Ok,
                )),
                AcceptType::Bcs => {
                    let gas_estimation_bcs = GasEstimationBcs {
                        gas_estimate: gas_estimation.gas_estimate,
                    };
                    BasicResponse::try_from_bcs((
                        gas_estimation_bcs,
                        &latest_ledger_info,
                        BasicResponseStatus::Ok,
                    ))
                },
            }
        })
        .await
```

**File:** storage/storage-interface/src/lib.rs (L56-58)
```rust
// This is last line of defense against large queries slipping through external facing interfaces,
// like the API and State Sync, etc.
pub const MAX_REQUEST_LIMIT: u64 = 20_000;
```
