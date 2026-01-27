# Audit Report

## Title
Missing Interval Bounds Validation in REST Discovery Causes Node Panic and Discovery Failures

## Summary
The `RestStream::new()` function in the network discovery module accepts an `interval_duration` parameter without validating that it falls within reasonable bounds. This allows misconfiguration to cause node panics (when zero), excessive REST API spam (when too small), or stale validator discovery (when too large), leading to discovery failures and potential node unavailability.

## Finding Description

The `RestStream::new()` function accepts an `interval_duration` parameter that is passed directly to create a periodic interval stream without any validation. [1](#0-0) 

This interval value originates from user-controlled configuration files through the `RestDiscovery.interval_secs` field. [2](#0-1) 

The configuration value is converted to a `Duration` and passed through without validation in the network builder. [3](#0-2) 

When the interval is created, the underlying `Interval::new()` function contains an assertion that the period must be non-zero. [4](#0-3) 

The configuration sanitizer validates many network settings but does not include any validation for discovery method intervals. [5](#0-4) 

**Attack Scenarios:**

1. **Zero Interval Panic**: If `interval_secs: 0` is configured, the node will panic during startup with the assertion failure, causing complete node unavailability.

2. **Spam Attack via Small Interval**: If `interval_secs: 1` or smaller values are configured, the node makes blocking REST API calls every second (or faster). The `poll_next()` implementation uses `block_on()` for each REST call. [6](#0-5) 

3. **Stale Discovery via Large Interval**: If `interval_secs: 86400` (1 day) or larger, the validator set information becomes stale, causing the node to fail discovering new validators or removing old ones.

## Impact Explanation

**Severity: Medium**

This issue allows node operators to misconfigure their nodes, leading to:

- **Node Unavailability** (panic on zero interval): Prevents the node from starting, causing complete unavailability of that validator/fullnode
- **Resource Exhaustion** (too small interval): Excessive REST API calls can overload the REST endpoint and waste computational resources
- **Discovery Failures** (too large interval): Stale validator set prevents proper peer discovery, degrading network connectivity

While this doesn't directly affect consensus safety or cause network-wide failures, it can cause:
- Individual validator nodes to become unavailable (affecting network participation)
- Degraded network connectivity due to stale discovery information
- Potential service disruption of REST endpoints from excessive polling

Per Aptos bug bounty criteria, this falls under **Medium Severity** as it causes state inconsistencies and operational issues requiring manual intervention to fix the configuration.

## Likelihood Explanation

**Likelihood: Medium**

This vulnerability can occur through:
- **Configuration mistakes**: Operators accidentally setting `interval_secs: 0` or unreasonable values
- **Copy-paste errors**: Using example configs with placeholder values
- **Misunderstanding units**: Confusing seconds with milliseconds

The likelihood is medium because:
- Configuration is typically done carefully by experienced operators (lowering probability)
- However, there's no validation to catch mistakes (no defense-in-depth)
- The consequence of zero interval is immediate and severe (node panic)
- Small intervals can go unnoticed initially but cause gradual resource exhaustion

## Recommendation

Add validation in `RestStream::new()` to enforce reasonable bounds:

```rust
pub(crate) fn new(
    network_context: NetworkContext,
    rest_url: url::Url,
    interval_duration: Duration,
    time_service: TimeService,
) -> Self {
    // Validate interval bounds
    const MIN_INTERVAL_SECS: u64 = 5; // Minimum 5 seconds to avoid spam
    const MAX_INTERVAL_SECS: u64 = 3600; // Maximum 1 hour to avoid staleness
    
    let interval_secs = interval_duration.as_secs();
    assert!(
        interval_secs >= MIN_INTERVAL_SECS,
        "REST discovery interval must be at least {} seconds, got {}",
        MIN_INTERVAL_SECS,
        interval_secs
    );
    assert!(
        interval_secs <= MAX_INTERVAL_SECS,
        "REST discovery interval must be at most {} seconds, got {}",
        MAX_INTERVAL_SECS,
        interval_secs
    );
    
    RestStream {
        network_context,
        rest_client: aptos_rest_client::Client::new(rest_url),
        interval: Box::pin(time_service.interval(interval_duration)),
    }
}
```

Additionally, add a configuration sanitizer check for discovery intervals to provide earlier validation feedback before node startup.

## Proof of Concept

**Scenario 1: Zero Interval Panic**

1. Create a node configuration file with REST discovery enabled:
```yaml
full_node_networks:
  - network_id: "public"
    discovery_methods:
      - rest:
          url: "https://fullnode.mainnet.aptoslabs.com/v1"
          interval_secs: 0  # Invalid: zero interval
```

2. Start the node with this configuration

3. **Expected Result**: Node panics during startup with assertion failure:
```
thread 'main' panicked at 'assertion failed: period > ZERO_DURATION: `period` must be non-zero.'
```

**Scenario 2: Excessive REST Calls**

1. Configure REST discovery with 1-second interval:
```yaml
discovery_methods:
  - rest:
      url: "https://fullnode.mainnet.aptoslabs.com/v1"
      interval_secs: 1  # Too small: causes spam
```

2. Monitor REST endpoint access logs

3. **Expected Result**: Node makes GET requests to `/v1/accounts/0x1/resource/0x1::stake::ValidatorSet` every second, potentially overwhelming the endpoint

**Scenario 3: Stale Validator Discovery**

1. Configure REST discovery with 24-hour interval:
```yaml
discovery_methods:
  - rest:
      url: "https://fullnode.mainnet.aptoslabs.com/v1"
      interval_secs: 86400  # Too large: 1 day causes staleness
```

2. Wait for validator set changes (e.g., new validator joins)

3. **Expected Result**: Node continues using stale validator information for up to 24 hours, failing to discover new validators and potentially attempting connections to removed validators

### Citations

**File:** network/discovery/src/rest.rs (L25-36)
```rust
    pub(crate) fn new(
        network_context: NetworkContext,
        rest_url: url::Url,
        interval_duration: Duration,
        time_service: TimeService,
    ) -> Self {
        RestStream {
            network_context,
            rest_client: aptos_rest_client::Client::new(rest_url),
            interval: Box::pin(time_service.interval(interval_duration)),
        }
    }
```

**File:** network/discovery/src/rest.rs (L42-51)
```rust
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Wait for delay, or add the delay for next call
        futures::ready!(self.interval.as_mut().poll_next(cx));

        // Retrieve the onchain resource at the interval
        // TODO there should be a better way than converting this to a blocking call
        let response = block_on(self.rest_client.get_account_resource_bcs::<ValidatorSet>(
            AccountAddress::ONE,
            "0x1::stake::ValidatorSet",
        ));
```

**File:** config/src/config/network_config.rs (L359-364)
```rust
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RestDiscovery {
    pub url: url::Url,
    pub interval_secs: u64,
}
```

**File:** network/builder/src/builder.rs (L379-385)
```rust
                DiscoveryMethod::Rest(rest_discovery) => DiscoveryChangeListener::rest(
                    self.network_context,
                    conn_mgr_reqs_tx.clone(),
                    rest_discovery.url.clone(),
                    Duration::from_secs(rest_discovery.interval_secs),
                    self.time_service.clone(),
                ),
```

**File:** crates/aptos-time-service/src/interval.rs (L30-34)
```rust
    pub fn new(delay: Sleep, period: Duration) -> Self {
        assert!(period > ZERO_DURATION, "`period` must be non-zero.");

        Self { delay, period }
    }
```

**File:** config/src/config/config_sanitizer.rs (L39-70)
```rust
impl ConfigSanitizer for NodeConfig {
    fn sanitize(
        node_config: &NodeConfig,
        node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        // If config sanitization is disabled, don't do anything!
        if node_config.node_startup.skip_config_sanitizer {
            return Ok(());
        }

        // Sanitize all of the sub-configs
        AdminServiceConfig::sanitize(node_config, node_type, chain_id)?;
        ApiConfig::sanitize(node_config, node_type, chain_id)?;
        BaseConfig::sanitize(node_config, node_type, chain_id)?;
        ConsensusConfig::sanitize(node_config, node_type, chain_id)?;
        DagConsensusConfig::sanitize(node_config, node_type, chain_id)?;
        ExecutionConfig::sanitize(node_config, node_type, chain_id)?;
        sanitize_failpoints_config(node_config, node_type, chain_id)?;
        sanitize_fullnode_network_configs(node_config, node_type, chain_id)?;
        IndexerGrpcConfig::sanitize(node_config, node_type, chain_id)?;
        InspectionServiceConfig::sanitize(node_config, node_type, chain_id)?;
        LoggerConfig::sanitize(node_config, node_type, chain_id)?;
        MempoolConfig::sanitize(node_config, node_type, chain_id)?;
        NetbenchConfig::sanitize(node_config, node_type, chain_id)?;
        StateSyncConfig::sanitize(node_config, node_type, chain_id)?;
        StorageConfig::sanitize(node_config, node_type, chain_id)?;
        InternalIndexerDBConfig::sanitize(node_config, node_type, chain_id)?;
        sanitize_validator_network_config(node_config, node_type, chain_id)?;

        Ok(()) // All configs passed validation
    }
```
