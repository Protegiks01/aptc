# Audit Report

## Title
Missing Rate Limit Bounds Validation in NetbenchConfig Leads to Division by Zero and Resource Exhaustion

## Summary
The `sanitize()` function in `NetbenchConfig` does not validate that `direct_send_per_second` and `rpc_per_second` are within reasonable bounds (e.g., greater than zero and less than a maximum threshold). This allows misconfiguration that leads to division by zero panics or resource exhaustion through infinite-rate message flooding in network benchmark testing scenarios.

## Finding Description
The `sanitize()` function in `NetbenchConfig` performs limited validation, only checking that netbench is not enabled on testnet or mainnet. [1](#0-0) 

However, it does not validate the rate limit parameters `direct_send_per_second` and `rpc_per_second`. [2](#0-1) 

These unchecked parameters are used in critical division operations in the network benchmark service: [3](#0-2) [4](#0-3) 

**Attack Scenarios:**

1. **Division by Zero (value = 0)**: If either parameter is set to 0, the calculation `1_000_000_000 / 0` causes a panic, crashing the node.

2. **Resource Exhaustion (extremely large values)**: If set to values approaching `u64::MAX`, the integer division `1_000_000_000 / u64::MAX` results in 0 nanoseconds, creating a zero-duration interval that causes the sender to flood the network with messages as fast as possible, exhausting CPU, memory, and network resources.

## Impact Explanation
This vulnerability is classified as **Low Severity** because:

1. Netbench is explicitly disabled on testnet and mainnet networks [5](#0-4) , limiting exposure to development and testing environments only.

2. The impact is limited to the misconfigured node itself - it does not affect consensus, other validators, or network security.

3. Exploitation requires configuration file access, not network-level attacks.

4. The affected component is a benchmarking/testing tool, not production-critical infrastructure.

However, it represents a violation of defensive programming principles and can cause operational disruption during development and testing activities.

## Likelihood Explanation
**Likelihood: Medium** 

The likelihood is medium because:
- Configuration errors are common in deployment scenarios
- Automated configuration generation tools might produce invalid values
- No runtime warnings or errors guide operators toward valid ranges
- The default values are reasonable [6](#0-5) , but custom configurations are vulnerable

## Recommendation
Add bounds validation to the `sanitize()` function to ensure rate limit parameters are within acceptable ranges:

```rust
impl ConfigSanitizer for NetbenchConfig {
    fn sanitize(
        node_config: &NodeConfig,
        _node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();

        if node_config.netbench.is_none() {
            return Ok(());
        }

        let netbench_config = node_config.netbench.unwrap();
        if !netbench_config.enabled {
            return Ok(());
        }

        // Validate rate limit bounds
        const MIN_RATE: u64 = 1;
        const MAX_RATE: u64 = 1_000_000;

        if netbench_config.direct_send_per_second < MIN_RATE 
            || netbench_config.direct_send_per_second > MAX_RATE {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                format!(
                    "direct_send_per_second must be between {} and {}, got {}",
                    MIN_RATE, MAX_RATE, netbench_config.direct_send_per_second
                ),
            ));
        }

        if netbench_config.rpc_per_second < MIN_RATE 
            || netbench_config.rpc_per_second > MAX_RATE {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                format!(
                    "rpc_per_second must be between {} and {}, got {}",
                    MIN_RATE, MAX_RATE, netbench_config.rpc_per_second
                ),
            ));
        }

        if let Some(chain_id) = chain_id {
            if chain_id.is_testnet() || chain_id.is_mainnet() {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    "The netbench application should not be enabled in testnet or mainnet!"
                        .to_string(),
                ));
            }
        }

        Ok(())
    }
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod test {
    use super::*;

    #[test]
    #[should_panic(expected = "attempt to divide by zero")]
    fn test_division_by_zero_direct_send() {
        // This test demonstrates the panic caused by zero value
        let config = NetbenchConfig {
            enabled: true,
            enable_direct_send_testing: true,
            direct_send_per_second: 0, // Zero value causes division by zero
            ..Default::default()
        };
        
        // This calculation will panic
        let _interval = Duration::from_nanos(1_000_000_000 / config.direct_send_per_second);
    }

    #[test]
    #[should_panic(expected = "attempt to divide by zero")]
    fn test_division_by_zero_rpc() {
        let config = NetbenchConfig {
            enabled: true,
            enable_rpc_testing: true,
            rpc_per_second: 0, // Zero value causes division by zero
            ..Default::default()
        };
        
        // This calculation will panic
        let _interval = Duration::from_nanos(1_000_000_000 / config.rpc_per_second);
    }

    #[test]
    fn test_extreme_value_resource_exhaustion() {
        let config = NetbenchConfig {
            enabled: true,
            direct_send_per_second: u64::MAX, // Extremely large value
            ..Default::default()
        };
        
        // This results in 0 nanoseconds, causing infinite-rate flooding
        let interval = Duration::from_nanos(1_000_000_000 / config.direct_send_per_second);
        assert_eq!(interval.as_nanos(), 0);
    }

    #[test]
    fn test_sanitize_should_reject_zero_values() {
        let node_config = NodeConfig {
            netbench: Some(NetbenchConfig {
                enabled: true,
                direct_send_per_second: 0,
                ..Default::default()
            }),
            ..Default::default()
        };

        // This should fail but currently passes (vulnerability)
        let result = NetbenchConfig::sanitize(&node_config, NodeType::Validator, None);
        // With the fix, this would return an error
    }
}
```

## Notes
- This vulnerability only affects development and testing environments since netbench is disabled on production networks.
- The testing suite uses values ranging from 1 to 1000 messages per second [7](#0-6) , which are all safe values.
- The fix should be applied as a defensive measure to prevent operational issues during development and testing activities.

### Citations

**File:** config/src/config/netbench_config.rs (L19-23)
```rust
    pub direct_send_per_second: u64,      // The interval (microseconds) between requests

    pub enable_rpc_testing: bool,
    pub rpc_data_size: usize,
    pub rpc_per_second: u64,
```

**File:** config/src/config/netbench_config.rs (L27-43)
```rust
impl Default for NetbenchConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_network_channel_size: 1000,
            netbench_service_threads: Some(2),

            enable_direct_send_testing: false,
            direct_send_data_size: 100 * 1024, // 100 KB
            direct_send_per_second: 1_000,

            enable_rpc_testing: false,
            rpc_data_size: 100 * 1024, // 100 KB
            rpc_per_second: 1_000,
            rpc_in_flight: 8,
        }
    }
```

**File:** config/src/config/netbench_config.rs (L46-77)
```rust
impl ConfigSanitizer for NetbenchConfig {
    fn sanitize(
        node_config: &NodeConfig,
        _node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();

        // If no netbench config is specified, there's nothing to do
        if node_config.netbench.is_none() {
            return Ok(());
        }

        // If netbench is disabled, there's nothing to do
        let netbench_config = node_config.netbench.unwrap();
        if !netbench_config.enabled {
            return Ok(());
        }

        // Otherwise, verify that netbench is not enabled in testnet or mainnet
        if let Some(chain_id) = chain_id {
            if chain_id.is_testnet() || chain_id.is_mainnet() {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    "The netbench application should not be enabled in testnet or mainnet!"
                        .to_string(),
                ));
            }
        }

        Ok(())
    }
```

**File:** network/benchmark/src/lib.rs (L352-352)
```rust
    let interval = Duration::from_nanos(1_000_000_000 / config.direct_send_per_second);
```

**File:** network/benchmark/src/lib.rs (L419-419)
```rust
    let interval = Duration::from_nanos(1_000_000_000 / config.rpc_per_second);
```

**File:** testsuite/forge-cli/src/suites/netbench.rs (L14-26)
```rust
        "net_bench_no_chaos_1000" => net_bench_no_chaos(MEGABYTE, 1000),
        "net_bench_no_chaos_900" => net_bench_no_chaos(MEGABYTE, 900),
        "net_bench_no_chaos_800" => net_bench_no_chaos(MEGABYTE, 800),
        "net_bench_no_chaos_700" => net_bench_no_chaos(MEGABYTE, 700),
        "net_bench_no_chaos_600" => net_bench_no_chaos(MEGABYTE, 600),
        "net_bench_no_chaos_500" => net_bench_no_chaos(MEGABYTE, 500),
        "net_bench_no_chaos_300" => net_bench_no_chaos(MEGABYTE, 300),
        "net_bench_no_chaos_200" => net_bench_no_chaos(MEGABYTE, 200),
        "net_bench_no_chaos_100" => net_bench_no_chaos(MEGABYTE, 100),
        "net_bench_no_chaos_50" => net_bench_no_chaos(MEGABYTE, 50),
        "net_bench_no_chaos_20" => net_bench_no_chaos(MEGABYTE, 20),
        "net_bench_no_chaos_10" => net_bench_no_chaos(MEGABYTE, 10),
        "net_bench_no_chaos_1" => net_bench_no_chaos(MEGABYTE, 1),
```
